package user

default allow = false

allow {
    some i
    input.request.method == "GET"
    input.request.path == "/users"
    data.oauth2.tokens.ac.roles[i] == "ROLE_admin"
}

allow {
    some i
    input.request.method == "GET"
    re_match("^/users/[a-zA-Z0-9]+$", input.request.path)
    data.oauth2.tokens.ac.roles[i] == "ROLE_admin"
}

allow {
    some i
    input.request.method == "POST"
    input.request.path == "/users"
    data.oauth2.tokens.ac.roles[i] == "ROLE_admin"
}

allow {
    some i
    input.request.method == "PUT"
    re_match("^/users/[a-zA-Z0-9]+$", input.request.path)
    data.oauth2.tokens.ac.roles[i] == "ROLE_admin"
}