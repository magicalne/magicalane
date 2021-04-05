# Magicalane - A QUIC based proxy

## Design

### Protocol

Once connection is setup, client will open a bi stream to send password validate request.

If password is validate, connection will be used to proxy requests of user.

Otherwise connection will be droped.

