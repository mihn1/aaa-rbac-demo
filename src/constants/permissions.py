# admin permissions
ADMIN_PERMISSION = "admin:all"

# log permissions
LOG_READ_PERMISSION = "logs:read"

# user permissions
USER_MANAGE_PERMISSION = "users:manage"
USER_READ_PERMISSION = "users:read"

# role permissions
ROLE_MANAGE_PERMISSION = "roles:manage"
ROLE_READ_PERMISSION = "roles:read"

# rule permissions
RULE_MANAGE_PERMISSION = "rules:manage"

ALL_PERMISSIONS = [
    ADMIN_PERMISSION,
    LOG_READ_PERMISSION,
    USER_MANAGE_PERMISSION,
    USER_READ_PERMISSION,
    ROLE_MANAGE_PERMISSION,
    ROLE_READ_PERMISSION,
    RULE_MANAGE_PERMISSION,
]

PERMISSION_DESCRIPTIONS = {
    ADMIN_PERMISSION: "Full administrative access",
    LOG_READ_PERMISSION: "View audit logs",
    USER_MANAGE_PERMISSION: "Create and manage user accounts",
    USER_READ_PERMISSION: "Read-only access to user directory",
    ROLE_MANAGE_PERMISSION: "Create and manage roles",
    ROLE_READ_PERMISSION: "Read-only access to role catalog",
    RULE_MANAGE_PERMISSION: "Create and manage detection rules",
}