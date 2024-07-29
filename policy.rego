package s3.authz

default allow = false

allow {
    input.user.role == "staccess-role"
}