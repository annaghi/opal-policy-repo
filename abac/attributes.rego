# Attribute-based Access Control (ABAC)
# -------------------------------------
#

package app.abac

default allow = false

allow {
	user_is_admin
}

allow {
	user_is_clinician
	action_is_read
    patients
}

user_is_admin {
	data.users[input.user].title == "admin"
}

user_is_clinician {
	data.users[input.user].title == "clinician"
}

user_is_visitor {
	data.users[input.user].title == "visitor"
}

action_is_read {
	input.action == "read"
}

action_is_update {
	input.action == "update"
}

patients[patients] {
	patients := data.clinicians[input.user].patients[_]
}
