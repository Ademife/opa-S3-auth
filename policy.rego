package s3.authz

# Define the default deny rule
default allow = false

# Define the allowed actions (This could be updated with the s3:actions needed)
allowed_actions :=  {"GetObject", "PutObject", "ListBucket"}

# Allow access if the user's role is 'staccess-role' and the action is in the allowed actions

allow {
    lower(input.user.role) == ["staccess-role", "st-admin"]
    allowed_actions[input.action]

}