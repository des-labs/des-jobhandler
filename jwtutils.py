import jwt
import datetime
import envvars

def encode_info(name, lastname, username, email, db, roles, ttl):
    encoded = jwt.encode({
            'name' : name,
            'lastname' : lastname,
            'username' : username,
            'email' : email,
            'db' : db,
            'roles' : roles,
            'exp' : datetime.datetime.utcnow() + datetime.timedelta(seconds=ttl)},
            envvars.JWT_HS256_SECRET,
            algorithm='HS256'
        )
    return encoded

def authenticated(cls_handler):
    def wrap_execute(handler_execute):
        def check_auth(handler, kwargs):
            auth = handler.request.headers.get("Authorization")
            response = {}
            if auth:
                parts = auth.split()
                handler._transforms = []
                nparts = len(parts)
                auth_type = parts[0].lower()
                if auth_type != 'bearer' or nparts==1 or nparts>2:
                    handler.set_status(200)
                    response["status"] = "error"
                    response["message"] = "Invalid header authorization"
                    handler.write(response)
                    handler.finish()
                    return
                token = parts[1]
                try:
                    decode = jwt.decode(token, envvars.JWT_HS256_SECRET, algorithms=["HS256"])
                except jwt.InvalidSignatureError:
                    response["status"] = "error"
                    response["message"] = "Signature verification failed"
                    handler.set_status(200)
                    handler.write(response)
                    handler.finish()
                    return
                except jwt.ExpiredSignatureError:
                    response["status"] = "error"
                    response["message"] = "Signature has expired"
                    handler.set_status(200)
                    handler.write(response)
                    handler.finish()
                    return
                except jwt.DecodeError:
                    response["status"] = "error"
                    response["message"] = "Invalid header string"
                    handler.set_status(500)
                    handler.write(response)
                    handler.finish()
                    return
                except Exception as e:
                    handler.set_status(200)
                    handler.write(e.message)
                    handler.finish()
                    return
                # If the token was valid, issue a new token to extend the session
                new_token = encode_info(
                    decode['name'],
                    decode['lastname'],
                    decode['username'],
                    decode['email'],
                    decode['db'],
                    decode['roles'],
                    envvars.JWT_TTL_SECONDS
                )
                decode = jwt.decode(new_token, envvars.JWT_HS256_SECRET, algorithms=["HS256"])
                handler._token_decoded = decode
                handler._token_encoded = new_token.decode(encoding='UTF-8')
            else:
                response["status"] = "error"
                response["message"] = "Missing authorization"
                handler.set_status(200)
                handler._transforms = []
                handler.write(response)
                handler.finish()
                return
            return True

        def _execute(self, transforms, *args, **kwargs):
            check_auth(self, kwargs)
            return handler_execute(self, transforms, *args, **kwargs)
        return _execute
    cls_handler._execute = wrap_execute(cls_handler._execute)
    return cls_handler
