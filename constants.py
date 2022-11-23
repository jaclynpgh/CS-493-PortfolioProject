# Response status code errors
# 400 Bad Request
bad_request_400 = {
    "Error": "The request object is missing at least one of the required attributes."}
# 403 Forbidden
forbidden_403_null = {"Error": "The request is forbidden. An id is required in the request."}
forbidden_403 = {"Error": "The request is forbidden. The boat is owned by someone else."}
error_load_403 = {"Error": "The request is forbidden. The load is already loaded on another boat"}

# 404 Not Found
not_found_404_boat = {"Error": "No boat with this boat_id exists"}
not_found_404_load = {"Error": "No load with this load_id exists"}
error_load_boat_404 = {"Error": "The specified boat and/or load does not exist"}
error_no_load_boat_404 ={"Error": "No boat with this boat_id is loaded with the load with this load_id"}

# 406 Not Acceptable (i.e., GET an response that is not the acceptable type)
not_acceptable_406 = {"Error": "Not an acceptable request. The endpoint does not support return of this MIME type."}
# 415  Unsupported Media Type (i.e., POST an unsupported type)
unsupported_media_415 = {"Error": "Unsupported media type. The endpoint does not accept this MIME type."}

boats = "boats"
loads = "loads"
users = "users"
get_method = False


