package oauth2

default authorize = {
    "allow": false,
    "code": 403,
    "message": "Authorization failed!" 
}

allow {
  data.appointment.allow
}
allow {
  data.user.allow
}
allow {
  data.healthrecord.allow
}

authorize = response {
  allow
  response := {
    "allow": true,
    "code": 200,
  }
}