

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
  (list (ntlm::pack-negotiate-flags *flags*)
	#xe2028233))

;; http://msdn.microsoft.com/en-us/library/cc669098.aspx
(defun test-lmowf-v1 ()
  (hd (lmowf-v1 "Password"))
  (hd #(#xe5 #x2c #xac #x67 #x41 #x9a #x9a #x22 #x4a #x3b #x10 #x8f #x3f #xa6 #xcb #x6d)))


;; 4.2.2.2.1 NTLMv1 Response http://msdn.microsoft.com/en-us/library/cc669102.aspx
(defun test-ntlm-v1-challenge-response ()
  (hd (desl (ntowf-v1 "Password")
	    (usb8 *server-challenge*)))
  (hd #(#x67 #xc4 #x30 #x11 #xf3 #x02 #x98 #xa2 #xad #x35 #xec #xe6 #x4f #x16 #x33 #x1c #x44 
	#xbd #xbe #xd9 #x27 #x84 #x1f #x94)))

;; 4.2.2.2.2 LMv1 Response http://msdn.microsoft.com/en-us/library/cc669103.aspx
(defun test-lm-v1-challenge-response ()
  (hd (lm-response-v1 (lmowf-v1 "Password")
		      (usb8 *server-challenge*)))
  (hd #(#x98 #xde #xf7 #xb8 #x7f #x88 #xaa #x5d #xaf #xe2 #xdf #x77 #x96 #x88 
	#xa1 #x72 #xde #xf1 #x1c #x7d #x5c #xcd #xef #x13)))


(defun make-key-exchange-key (&key (negotiate-lm-key t)
				request-non-nt-session-key 
				negotiate-extended-sessionsecurity)
  (key-exchange-key (session-base-key-v1 "Password")
		    (lm-response-v1 (lmowf-v1 "Password")
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
  (hd (make-key-exchange-key))
  (hd (usb8 *example-key-exchange-key*)))

;; 4.2.2.2.3 Encrypted Session Key http://msdn.microsoft.com/en-us/library/cc669104.aspx
(defun test-session-key ()
  (labels ((test (key-exchange-key)
	     (encrypted-session-key key-exchange-key
				    (usb8 *session-key*))))
    (hd (test (make-key-exchange-key :negotiate-lm-key nil)))
    (hd #(#x51 #x88 #x22 #xb1 #xb3 #xf3 #x50 #xc8 #x95 #x86 #x82 #xec #xbb #x3e #x3c #xb7))
    (terpri)
    (hd (test (make-key-exchange-key :negotiate-lm-key nil :request-non-nt-session-key t)))
    (hd #(#x74 #x52 #xca #x55 #xc2 #x25 #xa1 #xca #x04 #xb4 #x8f #xae #x32 #xcf #x56 #xfc))
    (terpri)
    (hd (test (make-key-exchange-key :negotiate-lm-key t)))
    (hd #(#x4c #xd7 #xbb #x57 #xd6 #x97 #xef #x9b #x54 #x9f #x02 #xb8 #xf9 #xb3 #x78 #x64))))


(defparameter *example-challenge-message*
  '(#x4e #x54 #x4c #x4d #x53 #x53 #x50 00 #x02 00 00 00 #x0c 00 #x0c 00
    #x38 00 00 00 #x33 #x82 #x02 #xe2 #x01 #x23 #x45 #x67 #x89 #xab #xcd #xef
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    #x06 00 #x70 #x17 00 00 00 #x0f #x53 00 #x65 00 #x72 00 #x76 00
    #x65 00 #x72 00))

;; 4.2.2.3 Messages http://msdn.microsoft.com/en-us/library/dd644758.aspx
(defun test-challenge-message ()
  (let ((msg (pack-challenge-message *flags* (usb8 *server-challenge*) 
                                     :target-name "Server"
                                     :version (make-ntlm-version 6 0 #x1770))))
    (hd msg)
    (hd (usb8 *example-challenge-message*))
    (list
     (unpack-challenge-message msg)
     (unpack-challenge-message (usb8 *example-challenge-message*)))))

(defun make-test-authenticate-message ()
  (pack-authenticate-message *flags*
			     :lm-response (lm-response-v1 (lmowf-v1 "Password") (usb8 *server-challenge*))
			     :nt-response (nt-response-v1 (ntowf-v1 "Password") (usb8 *server-challenge*))
			     :version (make-ntlm-version 5 1 2600)
			     :domain "Domain"
			     :username "User"
			     :workstation "COMPUTER"
			     :encrypted-session-key (encrypted-session-key 
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
;; My message is orderdered differently to the  example, but unpacks the same so
;; should be equivalent? 
(defun test-authenticate-message ()
  (let ((msg (make-test-authenticate-message)))
    (hd msg)
    (hd (usb8 *example-authenticate-message*))
    (list 
     (unpack-authenticate-message msg)
     (unpack-authenticate-message (usb8 *example-authenticate-message*)))))


;; 4.2.3.1.1 NTOWFv1() http://msdn.microsoft.com/en-us/library/cc669107.aspx
(defun test-ntowf-v1 ()
  (hd (ntowf-v1 "Password"))
  (hd #(#xa4 #xf4 #x9c #x40 #x65 #x10 #xbd #xca #xb6 #x82 #x4e #xe7 #xc3 #x0f #xd8 #x52)))

;; 4.2.3.1.2 http://msdn.microsoft.com/en-us/library/cc669100.aspx
(defun test-session-base-key ()
  (hd (session-base-key-v1 "Password"))
  (hd #(#xd8 #x72 #x62 #xb0 #xcd #xe4 #xb1 #xcb #x74 #x99 #xbe #xcc #xcd #xf1 #x07 #x84)))

;; 4.2.3.1.3 Key Exchange Key http://msdn.microsoft.com/en-us/library/cc669109.aspx
(defun test-key-exchange-key ()
  (hd 
   (key-exchange-key (session-base-key-v1 "Password")
		     (lm-response-v1* (lmowf-v1 "Password")
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
   (lm-response-v1* (lmowf-v1 "Password") 
		 (ntowf-v1 "Password") 
		 (usb8 *server-challenge*) 
		 (usb8 *client-challenge*) 
		 :negotiate-extended-sessionsecurity t))
  (hd #(#xaa #xaa #xaa #xaa #xaa #xaa #xaa #xaa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00)))

;; 4.2.3.2.2 NTLMv1 Response http://msdn.microsoft.com/en-us/library/cc669113.aspx
(defun test-nt-response ()
  (hd (nt-response-v1* (ntowf-v1 "Password") (usb8 *server-challenge*) (usb8 *client-challenge*) :negotiate-extended-sessionsecurity t))
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
(defun test-authenticate-message-* ()
  (let ((msg (pack-authenticate-message 
              *flags* 
              :lm-response (lm-response-v1* (lmowf-v1 "Password") 
                                            (ntowf-v1 "Password") 
                                            (usb8 *server-challenge*) 
                                            (usb8 *client-challenge*) 
                                            :negotiate-extended-sessionsecurity t)
              :nt-response (nt-response-v1* (ntowf-v1 "Password") 
                                            (usb8 *server-challenge*) 
                                            (usb8 *client-challenge*) 
                                            :negotiate-extended-sessionsecurity t)
              :domain "Domain" 
              :username "User" 
              :workstation "COMPUTER" 
              :version (make-ntlm-version 6 0 2600))))
    (hd msg)
    (hd (usb8 *example-authenticate-message-*))
    (list 
     (unpack-authenticate-message msg)
     (unpack-authenticate-message (usb8 *example-authenticate-message-*)))))

  
  
;; 4.2.4.1.1 NTOWFv2() and LMOWFv2() http://msdn.microsoft.com/en-us/library/cc669117.aspx
(defun test-ntowf-v2 ()
  (hd (ntowf-v2 "User" "Domain" (password-md4 "Password")))
  (hd #(#x0c #x86 #x8a #x40 #x3b #xfd #x7a #x93 #xa3 #x00 #x1e #xf2 #x2e #xf0 #x2e #x3f)))

;; 4.2.4.1.3 Temp http://msdn.microsoft.com/en-us/library/hh880685.aspx
(defun test-temp ()
  (hd (ntlm::make-temp 0 (usb8 *client-challenge*) "Server" "Domain"))
  (hd #(01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00   
	#xaa #xaa #xaa #xaa #xaa #xaa #xaa #xaa 00 00 00 00 02 00 #x0c 00 
	#x44 00 #x6f 00 #x6d 00 #x61 00 #x69 00 #x6e 00 01 00 #x0c 00   
	#x53 00 #x65 00 #x72 00 #x76 00 #x65 00 #x72 00 00 00 00 00   
        00 00 00 00)))

(defparameter *example-session-base-key-v2*
  '(#x8d #xe4 #x0c #xca #xdb #xc1 #x4a #x82 #xf1 #x5c #xb0 #xad #x0d #xe9 #x5c #xa3))
 
;; 4.2.4.1.2 Session Base Key http://msdn.microsoft.com/en-us/library/cc669118.aspx
(defun test-session-base-key-v2 ()
  (hd    
   (session-base-key-v2 (ntowf-v2 "User" "Domain" (password-md4 "Password"))
                        (usb8 *server-challenge*)
                        (usb8 *client-challenge*)
                        "Server"
                        "Domain"
                        0))
  (hd (usb8 *example-session-base-key-v2*)))

(defparameter *example-lmv2-response*
  '(#x86 #xc3 #x50 #x97 #xac #x9c #xec #x10 #x25 #x54 #x76 #x4a #x57 #xcc #xcc #x19 
    #xaa #xaa #xaa #xaa #xaa #xaa #xaa #xaa))

;; 4.2.4.2.1 LMv2 Response http://msdn.microsoft.com/en-us/library/cc669120.aspx
(defun test-lmv2-response ()
  (hd
   (lm-response-v2 (lmowf-v2 "User" "Domain" (password-md4 "Password"))
		   (usb8 *server-challenge*)
		   (usb8 *client-challenge*)))
  (hd (usb8 *example-lmv2-response*)))

(defparameter *example-ntlmv2-response*
  '(#x68 #xcd #x0a #xb8 #x51 #xe5 #x1c #x96 #xaa #xbc #x92 #x7b #xeb #xef #x6a #x1c))

;; 4.2.4.2.2 NTLMv2 Response http://msdn.microsoft.com/en-us/library/cc669121.aspx
(defun test-ntlmv2-response ()
  (hd
   (subseq 
    (nt-response-v2 (ntowf-v2 "User" "Domain" (password-md4 "Password"))
		    (usb8 *server-challenge*)
		    (usb8 *client-challenge*)
		    "Server"
		    "Domain"
		    0)
    0 16))
  (hd 
   (usb8 *example-ntlmv2-response*)))

(defparameter *example-encrypted-session-key-v2*
  '(#xc5 #xda #xd2 #x54 #x4f #xc9 #x79 #x90 #x94 #xce #x1c #xe9 #x0b #xc9 #xd0 #x3e))

;; 4.2.4.2.3 Encrypted Session Key http://msdn.microsoft.com/en-us/library/cc669122.aspx
(defun test-encrypted-session-key-v2 ()
  (hd
   (encrypted-session-key 
    (key-exchange-key 
     (session-base-key-v2 (ntowf-v2 "User" "Domain" (password-md4 "Password"))
			  (usb8 *server-challenge*)
			  (usb8 *client-challenge*)
			  "Server"
			  "Domain"
			  0)
     (lm-response-v2 (lmowf-v2 "User" "Domain" (password-md4 "Password"))
		     (usb8 *server-challenge*)
		     (usb8 *client-challenge*))
     (usb8 *server-challenge*)
     (lmowf-v2 "User" "Domain" (password-md4 "Password")))
    (usb8 *session-key*)))
  (hd
   (usb8 *example-encrypted-session-key-v2*)))

(defparameter *flags-v2*
  '(:NEGOTIATE-KEY-EXCH :NEGOTIATE-56 :NEGOTIATE-128
    :NEGOTIATE-VERSION :NEGOTIATE-TARGET-INFO :NEGOTIATE-EXTENDED-SESSIONSECURITY
    :TARGET-TYPE-SERVER :NEGOTIATE-ALWAYS-SIGN :NEGOTIATE-NTLM
    :NEGOTIATE-SEAL :NEGOTIATE-SIGN :NEGOTIATE-OEM :NEGOTIATE-UNICODE))

(defparameter *example-challenge-message-v2*
  '(#x4e #x54 #x4c #x4d #x53 #x53 #x50 00 #x02 00 00 00 #x0c 00 #x0c 00
    #x38 00 00 00 #x33 #x82 #x8a #xe2 01 #x23 #x45 #x67 #x89 #xab #xcd #xef
    00 00 00 00 00 00 00 00 #x24 00 #x24 00 #x44 00 00 00
    #x06 00 #x70 #x17 00 00 00 #x0f #x53 00 #x65 00 #x72 00 #x76 00
    #x65 00 #x72 00 #x02 00 #x0c 00 #x44 00 #x6f 00 #x6d 00 #x61 00
    #x69 00 #x6e 00 #x01 00 #x0c 00 #x53 00 #x65 00 #x72 00 #x76 00
    #x65 00 #x72 00 00 00 00 00))

;; 4.2.4.3 Messages http://msdn.microsoft.com/en-us/library/dd644747.aspx
(defun test-challenge-message-v2 ()
  (let ((msg 
         (pack-challenge-message *flags-v2*
                                 (usb8 *server-challenge*)
                                 :target-name "Server"
                                 :version (make-ntlm-version 6 0 2600)
                                 :target-info (make-target-info 
                                               :domain-name "Domain"
                                               :computer-name "Server"))))
    (hd msg)
    (hd (usb8 *example-challenge-message-v2*))
    (list
     (unpack-challenge-message msg)
     (unpack-challenge-message (usb8 *example-challenge-message-v2*)))))

(defparameter *example-authenticate-message-v2*
  '(#x4e #x54 #x4c #x4d #x53 #x53 #x50 00 #x03 00 00 00 #x18 00 #x18 00
    #x6c 00 00 00 #x54 00 #x54 00 #x84 00 00 00 #x0c 00 #x0c 00
    #x48 00 00 00 #x08 00 #x08 00 #x54 00 00 00 #x10 00 #x10 00
    #x5c 00 00 00 #x10 00 #x10 00 #xd8 00 00 00 #x35 #x82 #x88 #xe2
    #x05 #x01 #x28 #x0a 00 00 00 #x0f #x44 00 #x6f 00 #x6d 00 #x61 00
    #x69 00 #x6e 00 #x55 00 #x73 00 #x65 00 #x72 00 #x43 00 #x4f 00
    #x4d 00 #x50 00 #x55 00 #x54 00 #x45 00 #x52 00 #x86 #xc3 #x50 #x97
    #xac #x9c #xec #x10 #x25 #x54 #x76 #x4a #x57 #xcc #xcc #x19 #xaa #xaa #xaa #xaa
    #xaa #xaa #xaa #xaa #x68 #xcd #x0a #xb8 #x51 #xe5 #x1c #x96 #xaa #xbc #x92 #x7b
    #xeb #xef #x6a #x1c #x01 #x01 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 #xaa #xaa #xaa #xaa #xaa #xaa #xaa #xaa 00 00 00 00
    #x02 00 #x0c 00 #x44 00 #x6f 00 #x6d 00 #x61 00 #x69 00 #x6e 00
    #x01 00 #x0c 00 #x53 00 #x65 00 #x72 00 #x76 00 #x65 00 #x72 00
    00 00 00 00 00 00 00 00 #xc5 #xda #xd2 #x54 #x4f #xc9 #x79 #x90
    #x94 #xce #x1c #xe9 #x0b #xc9 #xd0 #x3e))

;; my code seems to order the message differently, but unpacks the same so should be equivalent 
;; to the example.
(defun test-authenticate-message-v2 ()
  (let ((msg
	 (pack-authenticate-message *flags-v2*
				    :lm-response 
				    (lm-response-v2 (lmowf-v2 "User" "Domain" (password-md4 "Password"))
						    (usb8 *server-challenge*)
						    (usb8 *client-challenge*))
				    :nt-response 
				    (nt-response-v2 (ntowf-v2 "User" "Domain" (password-md4 "Password"))
						    (usb8 *server-challenge*)
						    (usb8 *client-challenge*)
						    "Server"
						    "Domain"
						    0)
				    :domain "Domain"
				    :username "User"
				    :workstation "COMPUTER"
				    :encrypted-session-key
				    (encrypted-session-key 
				     (key-exchange-key 
				      (session-base-key-v2 (ntowf-v2 "User" "Domain" (password-md4 "Password"))
							   (usb8 *server-challenge*)
							   (usb8 *client-challenge*)
							   "Server"
							   "Domain"
							   0)
				      (lm-response-v2 (lmowf-v2 "User" "Domain" (password-md4 "Password"))
						      (usb8 *server-challenge*)
						      (usb8 *client-challenge*))
				      (usb8 *server-challenge*)
				      (lmowf-v2 "User" "Domain" (password-md4 "Password")))
				     (usb8 *session-key*))
				    :version (make-ntlm-version 5 1 2600))))
    (hd msg)
    (hd (usb8 *example-authenticate-message-v2*))
    (list 
     (unpack-authenticate-message msg)
     (unpack-authenticate-message (usb8 *example-authenticate-message-v2*)))))

  
(defun b64-usb8 (string)
  (cl-base64:base64-string-to-usb8-array string))

(defun usb8-b64 (usb8)
  (cl-base64:usb8-array-to-base64-string usb8))

(defun test-http-request (uri)
  (drakma:http-request uri
                       :method :post
                       :content "Hello"
                       :additional-headers 
                       `((:authorization . ,(format 
                                             nil "Negotiate ~A" 
                                             (usb8-b64 
                                              (pack-negotiate-message *flags* 
                                                                      :workstation "frank-lindev")))))))



                                              
                                                             
