//! Types used by the Public APIs

use std::fmt::Debug;
use std::net::SocketAddr;

use libc::sctp_sndrcvinfo;

/// SCTP Association ID Type
pub type AssociationId = i32;

/// Flags used by `sctp_bindx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindxFlags {
    /// Add the addresses passed (corresponding to `SCTP_BINDX_ADD_ADDR`)
    Add,

    /// Remove the addresses passed (corresponding to `SCTP_BINDX_REM_ADDR`)
    Remove,
}

/// SocketToAssociation: One-to-Many or One-to-One style Socket
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketToAssociation {
    /// One Association per Socket (TCP Style Socket.)
    OneToOne,

    /// Many Associations per Socket (UDP Style Socket.)
    OneToMany,
}

/// NotificationOrData: A type returned by a `sctp_recv` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationOrData {
    /// SCTP Notification received by an `sctp_recv` call.
    Notification(Notification),

    /// SCTP Data Received by an `sctp_recv` call.
    Data(ReceivedData),
}

/// Structure Representing SCTP Received Data.
///
/// This structure is returned by the `sctp_recv` API call. This contains in addition to 'received'
/// data, any ancillary data that is received during the underlying system call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedData {
    /// Received Message Payload.
    pub payload: Vec<u8>,

    /// Optional ancillary information about the received payload.
    pub rcv_info: Option<RcvInfo>,

    /// Optional ancillary information about the next call to `sctp_recv`.
    pub nxt_info: Option<NxtInfo>,
}

/// Structure Represnting Data to be Sent.
///
/// This structure contains actual paylod and optional ancillary data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendData {
    /// Received Message Payload.
    pub payload: Vec<u8>,

    /// Optional ancillary information used to send the data.
    pub snd_info: Option<SendInfo>,
}

/// Structure representing Ancilliary Send Information (See Section 5.3.4 of RFC 6458)
#[repr(C)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SendInfo {
    /// Stream ID of the stream to send the data on.
    pub sid: u16,

    /// Flags to be used while sending the data.
    pub flags: u16,

    /// Application Protocol ID to be used while sending the data.
    pub ppid: u32,

    /// Opaque context to be used while sending the data.
    pub context: u32,

    /// Association ID of the SCTP Association to be used while sending the data.
    pub assoc_id: AssociationId,
}

/// Structure Representing Ancillary Receive Information (See Section 5.3.5 of RFC 6458)
#[repr(C)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RcvInfo {
    /// Stream ID on which the data is received.
    pub sid: u16,

    /// Stream Sequence Number received in the data.
    pub ssn: u16,

    /// Flags for the received data.
    pub flags: u16,

    /// Application Protocol ID used by the sender while sending the data.
    pub ppid: u32,

    /// Transaction sequence number.
    pub tsn: u32,

    /// Cumulative sequence number.
    pub cumtsn: u32,

    /// Opaque context.
    pub context: u32,

    /// SCTP Association ID.
    pub assoc_id: AssociationId,
}

/// Structure representing Ancillary next information (See Section 5.3.5)
#[repr(C)]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct NxtInfo {
    /// Stream ID for the next received data.
    pub sid: u16,

    /// Flags for the next received data.
    pub flags: u16,

    /// Application protocol ID.
    pub ppid: u32,

    /// Length of the message to be used in the next `sctp_recv` call.
    pub length: u32,

    /// SCTP Association ID.
    pub assoc_id: AssociationId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// An `enum` representing the notifications received on the SCTP Sockets.
pub enum Notification {
    /// Association Change Notification. See Section 6.1.1 of RFC 6458.
    AssociationChange(AssociationChange),

    /// Peer Address Change Notification. See Section 6.1.2 of RFC 6458.
    PeerAddrChange(PeerAddrChange),

    /// Send Failed Notification. See Section 6.1.4 of RFC 6458. Deprecated.
    SendFailed(SendFailed),

    /// Remote Operation Error Notification. See Section 6.1.3 of RFC 6458.
    RemoteError(RemoteError),

    /// Shutdown Notification. See Section 6.1.5 of RFC 6458.
    Shutdown(Shutdown),

    /// Partial Delivery Event Notification. See Section 6.1.7 of RFC 6458.
    PartialDeliveryEvent(PdapiEvent),

    /// Adaptation Indication Notification. See Section 6.1.6 of RFC 6458.
    AdaptationIndication(AdaptationEvent),

    /// Authentication Event Notification. See Section 6.1.8 of RFC 6458.
    AuthenticationEvent(AuthkeyEvent),

    /// Sender Dry Event Notification. See Section 6.1.9 of RFC 6458.
    SenderDryEvent(SenderDryEvent),

    /// A Catchall Notification type for the Notifications that are not supported
    Unsupported,
}

/// AssociationChange: Structure returned as notification for Association Change.
///
/// To subscribe to this notification type, An application should call `sctp_subscribe_event` using
/// the [`Event`] type as [`Event::Association`].
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationChange {
    /// Type of the Notification always `SCTP_ASSOC_CHAGE`
    pub ev_type: Event,

    /// Notification Flags. Unused currently.
    pub flags: u16,

    /// Length of the notification data.
    pub length: u32,

    /// Association Change state. See also [`AssocChangeState`].
    pub state: AssocChangeState,

    /// Error when state is an error state and error information is available.
    pub error: u16,

    /// Maximum number of outbound streams.
    pub ob_streams: u16,

    /// Maximum number of inbound streams.
    pub ib_streams: u16,

    /// Association ID for the event.
    pub assoc_id: AssociationId,

    /// Additional data for the event.
    pub info: Vec<u8>,
}

/// PeerAddrChange: Structure returned as notification for Peer Address Change Event.
///
/// To subscribe to this notification type, an application should call `sctp_subscribe_event` using
/// the [`Event`] type as [`Event::Address`]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddrChange {
    /// Type of the notification. Always `Address`
    pub ev_type: Event,

    /// Notification flags. Unused currently.
    pub flags: u16,

    /// Length of the notification data including the notification header.
    pub length: u32,

    /// The affected address field holds the remote peer's address that is changed.
    pub aaddr: SocketAddr,

    /// This fields holds one of a number of values that communicate the event that happened to the
    /// address. They include: SCTP_ADDR_AVAILABLE, SCTP_ADDR_UNREACHABLE, SCTP_ADDR_REMOVED,
    /// SCTP_ADDR_ADDED, SCTP_ADDR_MADE_PRIM.
    pub state: u32,

    /// If the state was reached due to any error condition, any relevant error info is available here.
    pub error: u32,

    /// Holds the identifier for the association.
    pub assoc_id: i32,
}

/// SendFailed: Structure returned as notification for Send Failed Event.
///
/// To subscribe to this notification type, an application should call `sctp_subscribe_event` using
/// the [`Event`] type as [`Event::SendFailure`]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFailed {
    /// Type of the notification. Always `SendFailure`
    pub ev_type: Event,

    /// Notification flags. One of the following: SCTP_DATA_UNSENT, SCTP_DATA_SENT.
    pub flags: u16,

    /// Length of the notification data including the notification header and the payload.
    pub length: u32,

    /// The reason why the send failed.
    pub error: u32,

    /// This field includes the ancillary data used to send the undelivered message.
    pub ssf_info: sctp_sndrcvinfo,

    /// Holds the identifier for the association.
    pub assoc_id: AssociationId,

    /// The undelivered message or part of the undelivered message.
    pub data: Vec<u8>,
}


/// RemoteError: Structure returned as notification for Remote Error Event.
///
/// To subscribe to this notification type, an application should call `sctp_subscribe_event` using
/// the [`Event`] type as [`Event::PeerError`]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteError {
    /// Type of the notification. Always `RemoteError`
    pub ev_type: Event,

    /// Notification flags. Unused currently.
    pub flags: u16,

    /// Length of the notification data including the notification header and the payload.
    pub length: u32,

    /// The error code.
    pub error: u16,

    /// Holds the identifier for the association.
    pub assoc_id: AssociationId,

    /// The error message.
    pub data: Vec<u8>,
}

/// Shutdown: Structure returned as notification for Shutdown Event.
///
///To subscribe to this notification type, an application should call `sctp_subscribe_event` using
///the [`Event`] type as [`Event::Shutdown`]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shutdown {
    /// Type of the Notification always `SCTP_SHUTDOWN`
    pub ev_type: Event,

    /// Notification Flags. Unused currently.
    pub flags: u16,

    /// Length of the notification data.
    pub length: u32,

    /// Association ID for the event.
    pub assoc_id: AssociationId,
}

/// AdaptationEvent: Structure returned as notification for Adaptation Event.
///
/// To subscribe to this notification type, an application should call `sctp_subscribe_event` using
/// the [`Event`] type as [`Event::AdaptationLayer`]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdaptationEvent {
    /// Type of the Notification always `SCTP_ADAPTATION_INDICATION`
    pub ev_type: Event,

    /// Notification Flags. Unused currently.
    pub flags: u16,

    /// Length of the notification data.
    pub length: u32,

    /// Adaptation Indication.
    pub adaptation_ind: u32,

    /// Association ID for the event.
    pub assoc_id: AssociationId,
}

pub struct PdapiEvent {
    /// Type of the Notification always `SCTP_PARTIAL_DELIVERY_EVENT`
    pub ev_type: Event,

    /// Notification Flags. Unused currently.
    pub flags: u16,

    /// Length of the notification data.
    pub length: u32,

    /// Holds the Indication being sent to the application.
    pub indication: u32,

    /// Stream Number that was being partially delivered.
    pub stream: u32,

    /// Stream Sequence Number that was being partially delivered.
    pub seq: u32,

    /// Association ID for the event.
    pub assoc_id: AssociationId,
}

/// AuthkeyEvent: Structure returned as notification for Authentication Event.
///
/// To subscribe to this notification type, an application should call `sctp_subscribe_event` using
/// the [`Event`] type as [`Event::Authentication`]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthkeyEvent {
    /// Type of the Notification always `SCTP_AUTHENTICATION_EVENT`
    pub ev_type: Event,

    /// Notification Flags. Unused currently.
    pub flags: u16,

    /// Length of the notification data.
    pub length: u32,

    /// Holds the key number of the key being used.
    pub keynumber: u16,

    /// Holds the Indication being sent to the application.
    pub indication: u32,

    /// Association ID for the event.
    pub assoc_id: AssociationId,
}

/// SenderDryEvent: Structure returned as notification for Sender Dry Event.
///
/// To subscribe to this notification type, an application should call `sctp_subscribe_event` using
/// the [`Event`] type as [`Event::SenderDry`]
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderDryEvent {
    /// Type of the Notification always `SCTP_SENDER_DRY_EVENT`
    pub ev_type: Event,

    /// Notification Flags. Unused currently.
    pub flags: u16,

    /// Length of the notification data.
    pub length: u32,

    /// Association ID for the event.
    pub assoc_id: AssociationId,
}

/// Event: Used for Subscribing for SCTP Events
///
/// See [`sctp_subscribe_events`][`crate::Listener::sctp_subscribe_event`] for the usage.
#[repr(u16)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Event to receive ancillary information with every `sctp_recv`.
    DataIo = (1 << 15),

    /// Event related to association change.
    Association,

    /// Event related to peer address change.
    Address,

    /// Event related to send failure.
    SendFailure,

    /// Event related to error received from the peer.
    PeerError,

    /// Event related to indicate peer shutdown.
    Shutdown,

    /// Event related to indicate partial delivery.
    PartialDelivery,

    /// Event related to indicate peer's partial indication.
    AdaptationLayer,

    /// Authentication event.
    Authentication,

    /// Event related to sender having no outstanding user data.
    SenderDry,

    /// Event related to stream reset.
    StreamReset,

    /// Event related to association reset.
    AssociationReset,

    /// Event related to stream change.
    StreamChange,

    /// Send Failure Event indication. (The actual received information is different from the one
    /// received in the `SendFailed` event.)
    SendFailureEvent,

    /// Unknown Event: Used only when unknwon value is received as a `Notification`.
    Unknown,
}

impl Event {
    pub(crate) fn from_u16(val: u16) -> Self {
        match val {
            0x8000 => Event::DataIo,
            0x8001 => Event::Association,
            0x8002 => Event::Address,
            0x8003 => Event::SendFailure,
            0x8004 => Event::PeerError,
            0x8005 => Event::Shutdown,
            0x8006 => Event::PartialDelivery,
            0x8007 => Event::AdaptationLayer,
            0x8008 => Event::Authentication,
            0x8009 => Event::SenderDry,
            0x800A => Event::StreamReset,
            0x800B => Event::AssociationReset,
            0x800C => Event::StreamChange,
            0x800D => Event::SendFailureEvent,
            _ => Event::Unknown,
        }
    }
}

/// SubscribeEventAssocId: AssociationID Used for Event Subscription
///
/// Note: repr should be same as `AssociationId` (ie. `i32`)
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeEventAssocId {
    /// Subscribe to Future Association IDs
    Future,

    /// Subscribe to Current Association IDs
    Current,

    /// Subscribe to ALL Association IDs
    All,

    /// Subscribe to Association ID with a given value.
    Value(AssociationId),
}

impl From<SubscribeEventAssocId> for AssociationId {
    fn from(value: SubscribeEventAssocId) -> Self {
        match value {
            SubscribeEventAssocId::Future => 0 as Self,
            SubscribeEventAssocId::Current => 1 as Self,
            SubscribeEventAssocId::All => 2 as Self,
            SubscribeEventAssocId::Value(v) => v,
        }
    }
}

/// Association Change States
#[repr(u16)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssocChangeState {
    /// SCTP communication up.
    CommUp = 0,

    /// SCTP communication lost.
    CommLost,

    /// SCTP communication restarted.
    Restart,

    /// Shutdown complete.
    ShutdownComplete,

    /// Cannot start association.
    CannotStartAssoc,

    /// Unknown State: This value indicates an error
    Unknown,
}

impl AssocChangeState {
    pub(crate) fn from_u16(val: u16) -> Self {
        match val {
            0 => AssocChangeState::CommUp,
            1 => AssocChangeState::CommLost,
            2 => AssocChangeState::Restart,
            3 => AssocChangeState::ShutdownComplete,
            4 => AssocChangeState::CannotStartAssoc,
            _ => AssocChangeState::Unknown,
        }
    }
}

/// Constants related to `enum sctp_cmsg_type`
#[repr(i32)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CmsgType {
    Init = 0,
    SndRcv,
    SndInfo,
    RcvInfo,
    NxtInfo,
    PrInfo,
    AuthInfo,
    DstAddrV4,
    DstAddrV6,
}

/// Constants related to `enum sctp_sstat_state`
#[repr(i32)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ConnState {
    #[default]
    Empty = 0,
    Closed,
    CookieWait,
    CookieEchoed,
    Established,
    ShutdownPending,
    ShutdownSent,
    ShutdownReceived,
    ShutdownAckSent,

    Unknown, // Should never be seen.
}

impl ConnState {
    fn from_i32(val: i32) -> Self {
        match val {
            0 => Self::Empty,
            1 => Self::Closed,
            2 => Self::CookieWait,
            3 => Self::CookieEchoed,
            4 => Self::Established,
            5 => Self::ShutdownPending,
            6 => Self::ShutdownSent,
            7 => Self::ShutdownReceived,
            8 => Self::ShutdownAckSent,
            _ => Self::Unknown,
        }
    }
}

/// PeerAddress: Structure representing SCTP Peer Address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerAddress {
    pub assoc_id: AssociationId,
    pub address: std::net::SocketAddr,
    pub state: i32,
    pub cwnd: u32,
    pub srtt: u32,
    pub rto: u32,
    pub mtu: u32,
}

/// ConnStatus: Status of an SCTP Connection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnStatus {
    pub assoc_id: AssociationId,
    pub state: ConnState,
    pub rwnd: u32,
    pub unacked_data: u16,
    pub pending_data: u16,
    pub instreams: u16,
    pub outstreams: u16,
    pub fragmentation_pt: u32,
    pub peer_primary: PeerAddress,
}

pub(crate) mod internal;
