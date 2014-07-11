

(defpackage :ntlm-test
  (:use :cl :ntlm))

(in-package :ntlm-test)

;; examples taken from here
;; http://msdn.microsoft.com/en-us/library/cc669094.aspx

(defparameter *flags* '(:NEGOTIATE-KEY-EXCH :NEGOTIATE-56 :NEGOTIATE-128
        :NEGOTIATE-VERSION :TARGET-TYPE-SERVER :NEGOTIATE-ALWAYS-SIGN
        :NEGOTIATE-NTLM :NEGOTIATE-SEAL :NEGOTIATE-SIGN
        :NEGOTIATE-OEM :NEGOTIATE-UNICODE))
(defparameter *client-challenge* '(#xaa #xaa #xaa #xaa #xaa #xaa #xaa #xaa))
(defparameter *server-challenge* '(#x01 #x23 #x45 #x67 #x89 #xab #xcd #xef))
(defparameter *session-key* '(#x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55 #x55))



(defun test-flags ()
  "Compare a set of flags with the correct resulting value"
  (= (ntlm::pack-negotiate-flags *flags*)
     #xe2028233))

;; http://msdn.microsoft.com/en-us/library/cc669098.aspx
(defun test-lmowf-v1 ()
  (every #'=
         (lmowf-v1 "Password")
         #(#xe5 #x2c #xac #x67 #x41 #x9a #x9a #x22 #x4a #x3b #x10 #x8f #x3f #xa6 #xcb #x6d)))


;; 4.2.2.2.1 NTLMv1 Response http://msdn.microsoft.com/en-us/library/cc669102.aspx
(defun test-ntlm-v1-challenge-response ()
  (every #'=
         (desl (ntowf-v1 "Password")
	       (usb8 *server-challenge*))
         #(#x67 #xc4 #x30 #x11 #xf3 #x02 #x98 #xa2 #xad #x35 #xec #xe6 #x4f #x16 #x33 #x1c #x44 
           #xbd #xbe #xd9 #x27 #x84 #x1f #x94)))

;; 4.2.2.2.2 LMv1 Response http://msdn.microsoft.com/en-us/library/cc669103.aspx
(defun test-lm-v1-challenge-response ()
  (every #'=
         (lm-response (lmowf-v1 "Password")
		      (usb8 *server-challenge*))
         #(#x98 #xde #xf7 #xb8 #x7f #x88 #xaa #x5d #xaf #xe2 #xdf #x77 #x96 #x88 
           #xa1 #x72 #xde #xf1 #x1c #x7d #x5c #xcd #xef #x13)))


(defun make-key-exchange-key (&key (negotiate-lm-key t)
				request-non-nt-session-key 
				negotiate-extended-sessionsecurity)
  (key-exchange-key (session-base-key "Password")
		    (lm-response (lmowf-v1 "Password")
				 (usb8 *server-challenge*))
		    (usb8 *server-challenge*)
		    (lmowf-v1 "Password")
		    :negotiate-lm-key negotiate-lm-key
		    :request-non-nt-session-key request-non-nt-session-key
		    :negotiate-extended-sessionsecurity negotiate-extended-sessionsecurity))

(defparameter *example-key-exchange-key* 
  '(#xb0 #x9e #x37 #x9f #x7f #xbe #xcb #x1e #xaf #x0a #xfd #xcb #x03 #x83 #xc8 #xa0))

;; 4.2.2.2.2 LMv1 Response http://msdn.microsoft.com/en-us/library/cc669103.aspx
(defun test-lm-v1-key-exchange-key ()
  (every #'=
	 (make-key-exchange-key)
	 (usb8 *example-key-exchange-key*)))

;; 4.2.2.2.3 Encrypted Session Key http://msdn.microsoft.com/en-us/library/cc669104.aspx
(defun test-session-key ()
  (labels ((test (key-exchange-key)
	     (encrypted-session-key key-exchange-key
				    (usb8 *session-key*))))
    (hd (test (make-key-exchange-key :negotiate-lm-key nil)))
    (hd (test (make-key-exchange-key :negotiate-lm-key nil :request-non-nt-session-key t)))
    (hd (test (make-key-exchange-key :negotiate-lm-key t)))))

(defparameter *example-challenge-message*
  '(#x4e #x54 #x4c #x4d #x53 #x53 #x50 00 #x02 00 00 00 #x0c 00 #x0c 00
    #x38 00 00 00 #x33 #x82 #x02 #xe2 #x01 #x23 #x45 #x67 #x89 #xab #xcd #xef
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    #x06 00 #x70 #x17 00 00 00 #x0f #x53 00 #x65 00 #x72 00 #x76 00
    #x65 00 #x72 00))

;; 4.2.2.3 Messages http://msdn.microsoft.com/en-us/library/dd644758.aspx
(defun test-challenge-message ()
  (hd (pack-challenge-message *flags* (usb8 *server-challenge*) 
			      :target-name "Server"
			      :version (make-ntlm-version 6 0 #x1770)))
  (hd (usb8 *example-challenge-message*)))

(defun make-test-authenticate-message ()
  (pack-authenticate-message *flags*
			     :lm-response (lm-response (lmowf-v1 "Password") (usb8 *server-challenge*))
			     :nt-response (nt-response (ntowf-v1 "Password") (usb8 *server-challenge*))
			     :version (make-ntlm-version 5 1 2600)
			     :domain "Domain"
			     :username "User"
			     :workstation "COMPUTER"
			     :session-key (encrypted-session-key 
					   (make-key-exchange-key :negotiate-lm-key nil)
					   (usb8 *session-key*))))
 
(defparameter *example-authenticate-message*
  '(#x4e #x54 #x4c #x4d #x53 #x53 #x50 00 #x03 00 00 00 #x18 00 #x18 00   
    #x6c 00 00 00 #x18 00 #x18 00 #x84 00 00 00 #x0c 00 #x0c 00   
    #x48 00 00 00 #x08 00 #x08 00 #x54 00 00 00 #x10 00 #x10 00   
    #x5c 00 00 00 #x10 00 #x10 00 #x9c 00 00 00 #x35 #x82 #x80 #xe2   
    #x05 #x01 #x28 #x0a 00 00 00 #x0f #x44 00 #x6f 00 #x6d 00 #x61 00   
    #x69 00 #x6e 00 #x55 00 #x73 00 #x65 #x00 #x72 #x00 #x43 #x00 #x4f #x00   
    #x4d 00 #x50 00 #x55 00 #x54 00 #x45 00 #x52 00 #x98 #xde #xf7 #xb8   
    #x7f #x88 #xaa #x5d #xaf #xe2 #xdf #x77 #x96 #x88 #xa1 #x72 #xde #xf1 #x1c #x7d   
    #x5c #xcd #xef #x13 #x67 #xc4 #x30 #x11 #xf3 #x02 #x98 #xa2 #xad #x35 #xec #xe6   
    #x4f #x16 #x33 #x1c #x44 #xbd #xbe #xd9 #x27 #x84 #x1f #x94 #x51 #x88 #x22 #xb1   
    #xb3 #xf3 #x50 #xc8 #x95 #x86 #x82 #xec #xbb #x3e #x3c #xb7))

;; 4.2.2.3 Messages http://msdn.microsoft.com/en-us/library/dd644758.aspx
(defun test-authenticate-message ()
  (list 
   (unpack-authenticate-message (make-test-authenticate-message))
   (unpack-authenticate-message (usb8 *example-authenticate-message*))))


;; 4.2.3.1.1 NTOWFv1() http://msdn.microsoft.com/en-us/library/cc669107.aspx
(defun test-ntowf-v1 ()
  (every #'=
         (ntowf-v1 "Password")
         #(#xa4 #xf4 #x9c #x40 #x65 #x10 #xbd #xca #xb6 #x82 #x4e #xe7 #xc3 #x0f #xd8 #x52)))

;; 4.2.3.1.2 http://msdn.microsoft.com/en-us/library/cc669100.aspx
(defun test-session-base-key ()
  (every #'= 
         (session-base-key "Password")
         #(#xd8 #x72 #x62 #xb0 #xcd #xe4 #xb1 #xcb #x74 #x99 #xbe #xcc #xcd #xf1 #x07 #x84)))

;; 4.2.3.1.3 Key Exchange Key http://msdn.microsoft.com/en-us/library/cc669109.aspx
(defun test-key-exchange-key ()
  (hd 
   (key-exchange-key (session-base-key "Password")
		     (lm-response* (lmowf-v1 "Password")
				   (ntowf-v1 "Password")
				   (usb8 *server-challenge*)
				   (usb8 *client-challenge*)
				   :negotiate-extended-sessionsecurity t)
		     (usb8 *server-challenge*)
		     (lmowf-v1 "Password")
		     :negotiate-extended-sessionsecurity t))
  (hd #(#xeb #x93 #x42 #x9a #x8b #xd9 #x52 #xf8 #xb8 #x9c #x55 #xb8 #x7f #x47 #x5e #xdc)))

;; 4.2.3.2.1 LMv1 Response http://msdn.microsoft.com/en-us/library/cc669112.aspx
(defun test-lm-response ()
  (hd 
   (lm-response* (lmowf-v1 "Password") 
		 (ntowf-v1 "Password") 
		 (usb8 *server-challenge*) 
		 (usb8 *client-challenge*) 
		 :negotiate-extended-sessionsecurity t))
  (hd #(#xaa #xaa #xaa #xaa #xaa #xaa #xaa #xaa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00)))

;; 4.2.3.2.2 NTLMv1 Response http://msdn.microsoft.com/en-us/library/cc669113.aspx
(defun test-nt-response ()
  (hd (nt-response* (ntowf-v1 "Password") (usb8 *server-challenge*) (usb8 *client-challenge*) :negotiate-extended-sessionsecurity t))
  (hd #(#x75 #x37 #xf8 #x03 #xae #x36 #x71 #x28 #xca #x45 #x82 #x04 #xbd 
	#xe7 #xca #xf8 #x1e #x97 #xed #x26 #x83 #x26 #x72 #x32)))
  

(defparameter *example-authenticate-message-*
  '(#x4e #x54 #x4c #x4d #x53 #x53 #x50 #x00 #x03 00 00 00 #x18 00 #x18 00
    #x6c 00 00 00 #x18 00 #x18 00 #x84 00 00 00 #x0c 00 #x0c 00
    #x48 00 00 00 #x08 00 #x08 00 #x54 00 00 00 #x10 00 #x10 00
    #x5c 00 00 00 00 00 00 00 #x9c 00 00 00 #x35 #x82 #x08 #x82
    #x05 #x01 #x28 #x0a 00 00 00 #x0f #x44 00 #x6f 00 #x6d 00 #x61 00
    #x69 00 #x6e 00 #x55 00 #x73 00 #x65 00 #x72 00 #x43 00 #x4f 00
    #x4d 00 #x50 00 #x55 00 #x54 00 #x45 00 #x52 00 #xaa #xaa #xaa #xaa
    #xaa #xaa #xaa #xaa 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 #x75 #x37 #xf8 #x03 #xae #x36 #x71 #x28 #xca #x45 #x82 #x04
    #xbd #xe7 #xca #xf8 #x1e #x97 #xed #x26 #x83 #x26 #x72 #x32))

;; 4.2.3.3 Messages  http://msdn.microsoft.com/en-us/library/dd644690.aspx
(defun test-authenticate-message ()
  (list 
   (unpack-authenticate-message 
    (pack-authenticate-message *flags* 
			       :lm-response (lm-response* (lmowf-v1 "Password") 
							  (ntowf-v1 "Password") 
							  (usb8 *server-challenge*) 
							  (usb8 *client-challenge*) 
							  :negotiate-extended-sessionsecurity t)
			       :nt-response (nt-response* (ntowf-v1 "Password") 
							  (usb8 *server-challenge*) 
							  (usb8 *client-challenge*) 
							  :negotiate-extended-sessionsecurity t)
			       :domain "DOMAIN" 
			       :username "User" 
			       :workstation "COMPUTER" 
			       :version (make-ntlm-version 6 0 2600)))
   (unpack-authenticate-message (usb8 *example-authenticate-message-*))))

  
  
;; 4.2.4.1.1 NTOWFv2() and LMOWFv2() http://msdn.microsoft.com/en-us/library/cc669117.aspx
(defun test-ntowfv2-lmowfv2 ()
  (hd (ntowf-v2 "User" "Domain" (password-md4 "Password")))
  (hd #(#x0c #x86 #x8a #x40 #x3b #xfd #x7a #x93 #xa3 #x00 #x1e #xf2 #x2e #xf0 #x2e #x3f)))



; 00000000:   01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
; 00000010:   AA AA AA AA AA AA AA AA 00 00 00 00 01 00 0C 00 | ªªªªªªªª........
; 00000020:   53 00 65 00 72 00 76 00 65 00 72 00 02 00 0C 00 | S.e.r.v.e.r.....
; 00000030:   44 00 4F 00 4D 00 41 00 49 00 4E 00 00 00 00 00 | D.O.M.A.I.N.....
; 00000040:   00 00 00 00                                     | ....

;             01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00   
; 00000A0:    aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00   
; 00000B0:    44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00   
; 00000C0:    53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00   
; 00000D0:    00 00 00 00 
 
