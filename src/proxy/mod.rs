
trait Proxy {
    type LocalRecv;
    type LocalSend;
    type RemoteRecv;
    type RemoteSend;

    fn handshake();

    fn proxy();
}