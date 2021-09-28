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
    regex.match("^/users/[a-zA-Z0-9]+$", input.request.path)
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
    regex.match("^/users/[a-zA-Z0-9]+$", input.request.path)
    data.oauth2.tokens.ac.roles[i] == "ROLE_admin"
}