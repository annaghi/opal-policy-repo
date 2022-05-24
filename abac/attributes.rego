# Attribute-based Access Control (ABAC)
# -------------------------------------
#
# This example implements ABAC for a Pet Store API. The Pet Store API allows
# users to look at pets, adopt them, update their stats, and so on. The policy
# controls which users can perform actions on which resources. The policy implements
# a Attribute-based Access Control model where users, resources, and actions have
# attributes and the policy makes decisions based on those attributes.
#
# This example shows how to:
#
#	* Implement ABAC using Rego that leverages external data.
#	* Define helper rules that provide useful abstractions (e.g., `user_is_senior`).
#
# For more information see:
#
#	* Rego comparison to other systems: https://www.openpolicyagent.org/docs/latest/comparison-to-other-systems/
#
# Hint: The Coverage feature lets you view the policy statements that were executed
# when the policy was last evaluated. Try enabling Coverage and running evaluation
# with different inputs.

package app.abac

default allow = false

allow {
	user_is_admin
}

allow {
	user_is_clinician
	action_is_read
    user_has_patients
}

user_is_admin {
	data.user_attributes[input.user].title == "admin"
}

user_is_clinician {
	data.user_attributes[input.user].title == "clinician"
}

user_is_visitor {
	data.user_attributes[input.user].title == "visitor"
}

action_is_read {
	input.action == "read"
}

action_is_update {
	input.action == "update"
}

user_has_patients[patients] {
	patients := data.user_attributes[input.user].patients[_]
}

