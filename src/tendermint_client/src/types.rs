#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionMsgType {
    OpenTry,
    OpenAck,
    OpenConfirm,
}
