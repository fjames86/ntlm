
# NTLM
This is a library for handling the NTLM authentication protocol, commonly used by Microsoft Windows platforms.

Documentation for the protocol can be found here http://msdn.microsoft.com/en-us/library/cc236621.aspx

## 1. Introduction

The NTLM protocol consists of sending 3 messages:
* Client sends a NEGOTIATE message to server
* Server sends a CHALLENGE message to client, this contains a random number (server challenge)
* Client sends an AUTHENTICATE message back to server, this contains a calculation involving a hash 
of the user's password and the server challenge.

The server then computes the response it expects to recieve from the client, if the client's response 
matched the one the server was expecting then authentication was successful. 

Note that the whole process can be done (at both ends) without ever knowing the plain-text user password.


## 2. Usage

* Each message type has a pack- and unpack- function used to create a buffer and extract meaningful information from a buffer
* In test.lisp there is an example HTTP client and server (drakma/hunchentoot) showing how to use the functionality exported from the Lisp NTLM library
* Other transport protocols could be used (it is even possible to use a connection-less version of NTLM, although this is currently untested)

### 2.1 GSS interface
Provides a simplified interface using the GSSAPI exported from the glass package.

```
;; on the client 
NTLM> (logon-user "username" "password" "DOMAIN")
NTLM> (defvar *creds* (glass:acquire-credentials :ntlm nil))
NTLM> (defvar *client-context* nil)
NTLM> (multiple-value-bind (cxt buffer) (glass:initialize-security-context *creds*)
        (setf *client-context* cxt *buffer* buffer))
;; send *buffer* to the server 


;; on the server 
NTLM> (open-ntlm-database)
NTLM> (multiple-value-bind (cxt response) (glass:accept-security-context *creds* *buffer*)
        (setf *server-context* cxt *buffer* response))
;; send the *buffer* back to the client 

;; on the client, process the new message
NTLM> (multiple-value-bind (cxt response) (glass:initialize-security-context *client-context* :buffer *buffer*)
        (setf *client-context* cxt *buffer* response))
;; send back to the client

;; on the server 
NTLM> (glass:accept-security-context *server-context* *buffer*)
;; if we got here without an error then all went well and the user was authenticated

```

## 3. Local database
In order for your server to authenticate the client, it needs to somehow validate the client's request
by comparing the challenge we sent to the client and what we received. This requires knowledge of the client's 
password MD4 hash. One possibility is to proxy the call out to the local domain controller (Active Directory),
this lies beyond the scope of this tool.

Instead this library maintains a local shared database of usernames and passwords, 
which are stored in plain text on disk. 
All users which can be authenticated MUST have an entry added to this database.
The GSS methods to authenticate calls use this database to lookup passwords to compare against.

```
CL-USER> (ntlm:open-ntlm-database)
CL-USER> (ntlm:add-ntlm-user "User1" "1234")
CL-USER> (ntlm:add-ntlm-user "User2" "5555")
CL-USER> (ntlm:list-ntlm-users)
((:NAME "User1" :PASSWORD "1234") (:NAME "User2" :PASSWORD "5555"))
CL-USER> (ntlm:remove-ntlm-user "User1")
CL-USER> (ntlm:list-ntlm-users)
((:NAME "User2" :PASSWORD "5555"))
```

## 4. Notes

* Needs much more error checking, e.g. analyzing the flags to make sure information is present
* There are several different versions of "NTLM": v1, v2, with session security etc. 
These should all be handled seamlessly. Currently I just use some default values that work for me.


## 5. License
Licensed under the terms of the MIT license.

Frank James
July 2014

