
(asdf:defsystem :ntlm
  :name "NTLM"
  :author "Frank James <frank.a.james@gmail.com>"
  :description "NTLM library"
  :license "BSD"
  :components
  ((:file "package")
   (:file "messages" :depends-on ("package"))
   (:file "security" :depends-on ("messages")))
  :depends-on (:packet :ironclad :cl-base64))



