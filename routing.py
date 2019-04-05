from channels import route

from core.consumers import InfoRelayConsumer, GPGKeyConsumer, GPGDocumentConsumer, SecureRemoveConsumer

public_routes = [
    route(r'^(?P<uuid>[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/$', InfoRelayConsumer),
]

private_routes = [
    route('gpg-create-key', GPGKeyConsumer),
    route('gpg-document-handler', GPGDocumentConsumer),
    route('secure-remove', SecureRemoveConsumer)
]
