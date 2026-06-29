path "secret/metadata/*" {
  capabilities = ["list", "read"]
}

path "secret/data/*" {
  capabilities = ["read", "create", "update"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}
