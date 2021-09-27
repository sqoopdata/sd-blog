import org.forgerock.http.protocol.Request
import org.forgerock.http.protocol.Response
import org.forgerock.http.protocol.Status
import org.forgerock.util.AsyncFunction
import static org.forgerock.http.protocol.Response.newResponsePromise

bearerToken = contexts.oauth2.accessToken.token

if(bearerToken?.trim()) {
  Request isAuthorized = new Request()

  isAuthorized.uri = "http://127.0.0.1:8181/v1/data/oauth2/authorize"
  isAuthorized.method = "POST"
  isAuthorized.headers.put("Content-Type", "application/json")
  isAuthorized.entity.json = [ input: [ access_token: bearerToken, request: [ path: request.uri.path, method: request.method ]]]
  return http.send(context, isAuthorized)
    .thenAsync({ authZResponse ->
        data = authZResponse.entity.json
        logger.info("OPA Authorization Response: ${authZResponse.entity.json}, Status: ${authZResponse.status}")

        if(Status.OK == Status.valueOf(data.result.code) && data.result.allow == true) {
          return next.handle(context, request)
        } else { // 403
          Response res = new Response(Status.FORBIDDEN)
          res.entity.json = [message: "Access Denied!"]
          return newResponsePromise(res)
        }
    } as AsyncFunction)
} else { // bearer token not available == 401
    Response res = new Response(Status.UNAUTHORIZED)
    res.entity.json = [message: "Access Denied!"]
    return newResponsePromise(res)
}
