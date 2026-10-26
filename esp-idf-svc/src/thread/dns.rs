//! A DNS client for resolving and browsing DNS-SD services over Thread.
//!
//! The queries go to the DNS server of the Thread network. With the SRP client in
//! auto-start mode (see [`ThreadDriver::srp_autostart`]) that is the SRP server,
//! i.e. the DNS-SD server of a Border Router.
//!
//! OpenThread answers a query in a callback on its own task, with a response that
//! is only valid there. So the answer is copied into owned values, which the
//! query's future then returns.

use core::ffi::{c_char, c_void, CStr};
use core::net::Ipv6Addr;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::hal::task::asynch::Notification;
use crate::private::cstr::to_cstring_arg;
use crate::private::mutex::Mutex;
use crate::sys::{
    esp_openthread_get_instance, otDnsBrowseResponse, otDnsBrowseResponseGetHostAddress,
    otDnsBrowseResponseGetServiceInfo, otDnsBrowseResponseGetServiceInstance, otDnsClientBrowse,
    otDnsClientResolveServiceAndHostAddress, otDnsServiceInfo, otDnsServiceResponse,
    otDnsServiceResponseGetHostAddress, otDnsServiceResponseGetServiceInfo, otError,
    otError_OT_ERROR_NONE, otIp6Address, EspError, OT_DNS_MAX_LABEL_SIZE, OT_DNS_MAX_NAME_SIZE,
};

use crate::thread::{ot_esp, EspThread, Mode, NetifMode, ThreadDriver};

/// How much of a service's TXT data is read out of a response
const TXT_DATA_MAX_SIZE: usize = 512;

/// A resolved DNS-SD service instance
#[derive(Debug, Clone, Default)]
pub struct DnsServiceInfo {
    /// The TTL of the service record, in seconds
    pub ttl: u32,
    /// The port of the service
    pub port: u16,
    /// The priority of the service
    pub priority: u16,
    /// The weight of the service
    pub weight: u16,
    /// The name of the host the service runs on
    pub host_name: String,
    /// The IPv6 addresses of the host; empty if the response carried none
    pub host_addresses: Vec<Ipv6Addr>,
    /// The raw TXT data: a sequence of length-prefixed `key=value` strings
    pub txt_data: Vec<u8>,
    /// Whether the TXT data was longer than what was read out of the response
    pub txt_data_truncated: bool,
}

/// A service instance found by a DNS-SD browse
#[derive(Debug, Clone)]
pub struct DnsBrowseInstance {
    /// The instance label: the first label of the instance name
    pub label: String,
    /// The instance's service info, if the server sent it along
    pub info: Option<DnsServiceInfo>,
}

impl<T> ThreadDriver<'_, T>
where
    T: Mode,
{
    /// Resolve a DNS-SD service instance: its SRV and TXT records, and the
    /// addresses of its host if the server did not send them along.
    ///
    /// Arguments:
    /// - `instance_label`: The instance label, e.g. `ABCD1234`.
    /// - `service_name`: The service name, e.g. `_matter._tcp.default.service.arpa`.
    pub async fn dns_resolve_service_and_host_address(
        &self,
        instance_label: &str,
        service_name: &str,
    ) -> Result<DnsServiceInfo, EspError> {
        let instance_label = to_cstring_arg(instance_label)?;
        let service_name = to_cstring_arg(service_name)?;

        let query = self.dns_query(|context| unsafe {
            otDnsClientResolveServiceAndHostAddress(
                esp_openthread_get_instance(),
                instance_label.as_ptr(),
                service_name.as_ptr(),
                Some(on_service_response),
                context,
                core::ptr::null(),
            )
        })?;

        query.wait().await
    }

    /// Browse a DNS-SD service: enumerate its instances.
    ///
    /// Arguments:
    /// - `service_name`: The service name, e.g. `_matterc._udp.default.service.arpa`.
    pub async fn dns_browse(&self, service_name: &str) -> Result<Vec<DnsBrowseInstance>, EspError> {
        let service_name = to_cstring_arg(service_name)?;

        let query = self.dns_query(|context| unsafe {
            otDnsClientBrowse(
                esp_openthread_get_instance(),
                service_name.as_ptr(),
                Some(on_browse_response),
                context,
                core::ptr::null(),
            )
        })?;

        query.wait().await
    }

    /// Send a query with `send`, which gets the context to pass to the
    /// query's callback.
    fn dns_query<R>(
        &self,
        send: impl FnOnce(*mut c_void) -> otError,
    ) -> Result<Arc<DnsQuery<R>>, EspError> {
        let query = Arc::new(DnsQuery::new());

        // The callback takes over this reference: OpenThread invokes it exactly
        // once for a query it sent, on a response or a time-out. So the query
        // outlives a future dropped in the meantime.
        let context = Arc::into_raw(query.clone()) as *mut c_void;

        let _lock = self.inner();

        if let Err(err) = ot_esp!(send(context)) {
            drop(unsafe { Arc::from_raw(context as *const DnsQuery<R>) });

            return Err(err);
        }

        Ok(query)
    }
}

impl<T> EspThread<'_, T>
where
    T: NetifMode,
{
    /// Resolve a DNS-SD service instance: its SRV and TXT records, and the
    /// addresses of its host if the server did not send them along.
    ///
    /// Arguments:
    /// - `instance_label`: The instance label, e.g. `ABCD1234`.
    /// - `service_name`: The service name, e.g. `_matter._tcp.default.service.arpa`.
    pub async fn dns_resolve_service_and_host_address(
        &self,
        instance_label: &str,
        service_name: &str,
    ) -> Result<DnsServiceInfo, EspError> {
        self.driver()
            .dns_resolve_service_and_host_address(instance_label, service_name)
            .await
    }

    /// Browse a DNS-SD service: enumerate its instances.
    ///
    /// Arguments:
    /// - `service_name`: The service name, e.g. `_matterc._udp.default.service.arpa`.
    pub async fn dns_browse(&self, service_name: &str) -> Result<Vec<DnsBrowseInstance>, EspError> {
        self.driver().dns_browse(service_name).await
    }
}

/// A query in flight, shared by its future and its callback
struct DnsQuery<R> {
    result: Mutex<Option<Result<R, EspError>>>,
    done: Notification,
}

impl<R> DnsQuery<R> {
    const fn new() -> Self {
        Self {
            result: Mutex::new(None),
            done: Notification::new(),
        }
    }

    fn complete(&self, result: Result<R, EspError>) {
        *self.result.lock() = Some(result);
        self.done.notify_lsb();
    }

    async fn wait(&self) -> Result<R, EspError> {
        loop {
            if let Some(result) = self.result.lock().take() {
                return result;
            }

            self.done.wait().await;
        }
    }
}

unsafe extern "C" fn on_service_response(
    error: otError,
    response: *const otDnsServiceResponse,
    context: *mut c_void,
) {
    let query = unsafe { Arc::from_raw(context as *const DnsQuery<DnsServiceInfo>) };

    let result = ot_esp!(error).and_then(|()| {
        read_service_info(
            |info| unsafe { otDnsServiceResponseGetServiceInfo(response, info) },
            |host_name, index, addr, ttl| unsafe {
                otDnsServiceResponseGetHostAddress(response, host_name, index, addr, ttl)
            },
        )
    });

    query.complete(result);
}

unsafe extern "C" fn on_browse_response(
    error: otError,
    response: *const otDnsBrowseResponse,
    context: *mut c_void,
) {
    let query = unsafe { Arc::from_raw(context as *const DnsQuery<Vec<DnsBrowseInstance>>) };

    let result = ot_esp!(error).map(|()| {
        let mut instances = Vec::new();
        let mut label = [0 as c_char; OT_DNS_MAX_LABEL_SIZE as usize];

        for index in 0..u16::MAX {
            let error = unsafe {
                otDnsBrowseResponseGetServiceInstance(
                    response,
                    index,
                    label.as_mut_ptr(),
                    label.len() as _,
                )
            };

            if error != otError_OT_ERROR_NONE {
                break;
            }

            let info = read_service_info(
                |info| unsafe { otDnsBrowseResponseGetServiceInfo(response, label.as_ptr(), info) },
                |host_name, index, addr, ttl| unsafe {
                    otDnsBrowseResponseGetHostAddress(response, host_name, index, addr, ttl)
                },
            )
            .ok();

            instances.push(DnsBrowseInstance {
                label: unsafe { CStr::from_ptr(label.as_ptr()) }
                    .to_string_lossy()
                    .into_owned(),
                info,
            });
        }

        instances
    });

    query.complete(result);
}

/// Read the info of a service with `get_info`, and all the addresses of its
/// host with `get_address`.
fn read_service_info(
    get_info: impl FnOnce(*mut otDnsServiceInfo) -> otError,
    get_address: impl Fn(*const c_char, u16, *mut otIp6Address, *mut u32) -> otError,
) -> Result<DnsServiceInfo, EspError> {
    // On the heap rather than on the stack of the OpenThread task
    let mut host_name: Vec<c_char> = vec![0; OT_DNS_MAX_NAME_SIZE as usize];
    let mut txt_data = vec![0; TXT_DATA_MAX_SIZE];

    let mut info: otDnsServiceInfo = unsafe { core::mem::zeroed() };
    info.mHostNameBuffer = host_name.as_mut_ptr();
    info.mHostNameBufferSize = host_name.len() as _;
    info.mTxtData = txt_data.as_mut_ptr();
    info.mTxtDataSize = txt_data.len() as _;

    ot_esp!(get_info(&mut info))?;

    txt_data.truncate(info.mTxtDataSize as _);

    let mut host_addresses = Vec::new();

    for index in 0..u16::MAX {
        let mut addr: otIp6Address = unsafe { core::mem::zeroed() };
        let mut ttl = 0;

        if get_address(host_name.as_ptr(), index, &mut addr, &mut ttl) != otError_OT_ERROR_NONE {
            break;
        }

        host_addresses.push(Ipv6Addr::from(unsafe { addr.mFields.m8 }));
    }

    if host_addresses.is_empty() {
        let addr = Ipv6Addr::from(unsafe { info.mHostAddress.mFields.m8 });

        if !addr.is_unspecified() {
            host_addresses.push(addr);
        }
    }

    Ok(DnsServiceInfo {
        ttl: info.mTtl,
        port: info.mPort,
        priority: info.mPriority,
        weight: info.mWeight,
        host_name: unsafe { CStr::from_ptr(host_name.as_ptr()) }
            .to_string_lossy()
            .into_owned(),
        host_addresses,
        txt_data,
        txt_data_truncated: info.mTxtDataTruncated,
    })
}
