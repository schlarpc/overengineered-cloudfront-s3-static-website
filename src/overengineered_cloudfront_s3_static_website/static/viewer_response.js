function handler(event) {
    var response = event.response;
    if ("x-amz-website-redirect-location" in response.headers) {
        response.headers["location"] = response.headers["x-amz-website-redirect-location"];
        response.statusCode = 301;
        response.statusDescription = "Moved Permanently";
    }
    return response;
}
