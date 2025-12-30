package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the rbac-enum tool
func InputSchema() schema.JSON {
	actionSchema := schema.String()
	actionSchema.Description = "Action to perform: whoami, can-i, list-roles, list-bindings, list-all, check-escalation"

	verbSchema := schema.String()
	verbSchema.Description = "Verb to check for can-i (e.g., get, list, create, delete, patch, exec)"

	resourceSchema := schema.String()
	resourceSchema.Description = "Resource type to check for can-i (e.g., pods, secrets, configmaps)"

	subresourceSchema := schema.String()
	subresourceSchema.Description = "Subresource to check (e.g., exec, log, portforward)"

	resourceNameSchema := schema.String()
	resourceNameSchema.Description = "Specific resource name for can-i check"

	namespaceSchema := schema.String()
	namespaceSchema.Description = "Namespace to check (optional)"

	allNamespacesSchema := schema.Bool()
	allNamespacesSchema.Description = "Check all namespaces"

	kubeconfigSchema := schema.String()
	kubeconfigSchema.Description = "Path to kubeconfig file (optional)"

	contextSchema := schema.String()
	contextSchema.Description = "Kubernetes context to use (optional)"

	asUserSchema := schema.String()
	asUserSchema.Description = "Impersonate this user (optional)"

	asGroupSchema := schema.Array(schema.String())
	asGroupSchema.Description = "Impersonate these groups (optional)"

	dangerousVerbsSchema := schema.Array(schema.String())
	dangerousVerbsSchema.Description = "Additional verbs to check for escalation (default: create, delete, patch, exec)"

	timeoutSchema := schema.Int()
	timeoutSchema.Description = "Timeout in seconds (optional, default: 60)"

	return schema.Object(map[string]schema.JSON{
		"action":          actionSchema,
		"verb":            verbSchema,
		"resource":        resourceSchema,
		"subresource":     subresourceSchema,
		"resource_name":   resourceNameSchema,
		"namespace":       namespaceSchema,
		"all_namespaces":  allNamespacesSchema,
		"kubeconfig":      kubeconfigSchema,
		"context":         contextSchema,
		"as_user":         asUserSchema,
		"as_group":        asGroupSchema,
		"dangerous_verbs": dangerousVerbsSchema,
		"timeout":         timeoutSchema,
	}, "action") // action is required
}

// OutputSchema defines the output schema for the rbac-enum tool
func OutputSchema() schema.JSON {
	successSchema := schema.Bool()
	successSchema.Description = "Whether the action succeeded"

	// Whoami output
	usernameSchema := schema.String()
	usernameSchema.Description = "Current authenticated username"

	groupsSchema := schema.Array(schema.String())
	groupsSchema.Description = "Groups the user belongs to"

	uidSchema := schema.String()
	uidSchema.Description = "User identifier"

	// Can-i output
	allowedSchema := schema.Bool()
	allowedSchema.Description = "Whether the action is allowed"

	reasonSchema := schema.String()
	reasonSchema.Description = "Reason for the decision"

	// Role/binding listings
	rolesSchema := schema.Array(schema.Any())
	rolesSchema.Description = "List of roles"

	clusterRolesSchema := schema.Array(schema.Any())
	clusterRolesSchema.Description = "List of cluster roles"

	roleBindingsSchema := schema.Array(schema.Any())
	roleBindingsSchema.Description = "List of role bindings"

	clusterRoleBindingsSchema := schema.Array(schema.Any())
	clusterRoleBindingsSchema.Description = "List of cluster role bindings"

	// Escalation check
	dangerousPermissionsSchema := schema.Array(schema.Any())
	dangerousPermissionsSchema.Description = "List of dangerous permissions found"

	escalationPathsSchema := schema.Array(schema.Any())
	escalationPathsSchema.Description = "Potential privilege escalation paths"

	executionTimeSchema := schema.Int()
	executionTimeSchema.Description = "Execution time in milliseconds"

	errorSchema := schema.String()
	errorSchema.Description = "Error message if failed"

	return schema.Object(map[string]schema.JSON{
		"success":                 successSchema,
		"username":                usernameSchema,
		"groups":                  groupsSchema,
		"uid":                     uidSchema,
		"allowed":                 allowedSchema,
		"reason":                  reasonSchema,
		"roles":                   rolesSchema,
		"cluster_roles":           clusterRolesSchema,
		"role_bindings":           roleBindingsSchema,
		"cluster_role_bindings":   clusterRoleBindingsSchema,
		"dangerous_permissions":   dangerousPermissionsSchema,
		"escalation_paths":        escalationPathsSchema,
		"execution_time_ms":       executionTimeSchema,
		"error":                   errorSchema,
	})
}
