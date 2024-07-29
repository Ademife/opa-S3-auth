package policy_test

import data.s3.authz

test_allow_if_storageaccessrole {
    allow_test_input := {
        "user": {
        "role": "staccess-role"
    },
        "action": "GetObject",
        "resource": "arn:aws:s3:::s3-bucket/any-object"
    }
    
    result := data.s3.authz.allow with input as allow_test_input
    result == true
}

test_deny_if_not_storageaccessrole {
    deny_test_input := {
        "user": {
        "role": ["admin-role"]
    },
        "action": "GetObject",
        "resource": "arn:aws:s3:::s3-bucket/any-object"
    }
    
    result := data.s3.authz.allow with input as deny_test_input
    result == false
}

test_deny_if_not_storageaccessrole {
    deny_test_input := {
        "user": {
        "role": ["st-accessrole"]
    },
        "action": "PutObject",
        "resource": "arn:aws:s3:::s3-bucket/any-object"
    }
    
    result := data.s3.authz.allow with input as deny_test_input
    result == false
}

test_allow_if_storageaccessrole {
    allow_test_input := {
        "user": {
        "role": "staccess-role"
    },
        "action": "PutObject",
        "resource": "arn:aws:s3:::s3-bucket/any-object"
    }
    
    result := data.s3.authz.allow with input as allow_test_input
    result == true
}

test_deny_if__role_not_provided {
    test_input := {
        "user": {},
        "action": "PutObject",
        "resource": "arn:aws:s3:::s3-bucket/any-object"
    }

    result := data.s3.authz.allow with input as test_input
    result == false
}

test_deny_if__role_case_differs {
    test_input := {
        "user": {"role": "StorageAccess-role"},
        "action": "PutObject",
        "resource": "arn:aws:s3:::s3-bucket/any-object"
    }

    result := data.s3.authz.allow with input as test_input
    result == false
}

test_allow_with_unexpected_fields{
    test_input := {
        "user": {
        "role": "staccess-role",
        "extra": "unexpected"
    },
        "action": "PutObject",
        "resource": "arn:aws:s3:::s3-bucket/any-object"
    }
    
    result := data.s3.authz.allow with input as test_input
    result == true
}

