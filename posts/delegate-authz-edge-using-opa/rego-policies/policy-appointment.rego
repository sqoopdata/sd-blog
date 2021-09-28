package appointment

default allow = false

allow {
    some i,j
    roles := ["ROLE_admin", "ROLE_patient"]
    input.request.method == "GET"
    input.request.path == "/appointments"
    data.oauth2.tokens.ac.roles[i] == roles[j]
}

allow {
    some i,j
    roles := ["ROLE_admin", "ROLE_patient"]
    input.request.method == "GET"
    regex.match("^/appointments/[0-9]+$", input.request.path)
    data.oauth2.tokens.ac.roles[i] == roles[j]
}

allow {
    some i,j
    roles := ["ROLE_admin", "ROLE_patient"]
    input.request.method == "POST"
    input.request.path == "/appointments"
    data.oauth2.tokens.ac.roles[i] == roles[j]
}

allow {
    some i,j
    roles := ["ROLE_admin"]
    input.request.method == "PUT"
    regex.match("^/appointments/[0-9]+$", input.request.path)
    data.oauth2.tokens.ac.roles[i] == roles[j]
}