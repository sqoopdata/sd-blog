package healthrecord

default allow = false

allow {
    some i,j
    roles := ["ROLE_doctor"]
    input.request.method == "GET"
    input.request.path == "/healthrecords"
    data.oauth2.tokens.ac.roles[i] == roles[j]
}

allow {
    some i
    roles := ["ROLE_doctor"]
    input.request.method == "POST"
    input.request.path == "/healthrecords"
    data.oauth2.tokens.ac.roles[i] == roles[j]
}

allow {
    some i
    roles := ["ROLE_doctor"]
    input.request.method == "PUT"
    re_match("^/healthrecords/[0-9]+$", input.request.path)
    data.oauth2.tokens.ac.roles[i] == roles[j]
}