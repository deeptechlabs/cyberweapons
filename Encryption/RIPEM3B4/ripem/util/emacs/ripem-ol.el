;; Functions for calling RIPEM from emacs mail.
;; Version 1.2.1
;; This file is public domain courtesy of RSA Data Security. Inc.

;; Modified Jan 18 1993 by jefft@rsa.com  
;;; Fixed simple bug in ripem-list-users.

;; Modified Jan 6 1993 by Christopher Owens (owens@cs.uchicago.edu)
;;; 1) Replaced hard-coded file names with variables, and attempted to
;;;    do something vaguely reasonable with environment variables.
;;; 2) Eliminating the passing of the key-to-secret-key via the -k command
;;;    line option, which is a security hole.  Instead, we use the "-k -"
;;;    option, which tells RIPEM to read the key from standard input.
;;;    This requires some messing with a temp buffers, because we don't
;;;    want to (visibly) stuff the key into the current buffer, either.
;;; 3) Added progress indication
;;; 4) ripem-sign takes optional argument SIGN-CLEAR; if T then use
;;;    encryption mode mic-clear rather than mic-only
;;; 5) ripem-receive operates only on the body of the message (between the PEM
;;;    banners, and offers a bail-out option if those banners are not found
;;; 6) ripem-generate shows diagnostic output.

;; To install, add the expresion (load "/home/local/ripem/util/emacs/ripem.el") 
;;  to the file ~/.emacs or to /home/local/emacs/lisp/default, where
;;  /home/local/ripem/util/emacs is the directory where this file is, and
;;  /home/local/emacs is the directory where emacs is installed.

;; The ripem-executable is specified by ripem-program-name

;; The public key file is specified in the variable ripem-public-key-file
;; and the secret key file  in the variable ripem-secret-key-file
;; These default to /usr/local/etc/rpubkeys and ~/.ripemprv.  If the user
;; has specified the environment variables 

;; Be sure to generate your keys first.  Use ESC-x ripem-generate.
;; The commands ESC-x ripem-sign and ripem-encrypt use the -h option when
;;   preparing the message, which means that the header with the To: fields,
;;   etc. should be at the top of the buffer, followed by a blank line or
;;   a line with "--text follows this line--".
;; Use ESC-x ripem-receive to decipher the RIPEM message in the buffer.
;; Use ESC-x ripem-list-users to display the user names in the public key file.
;; For more info, type C-h f and then the name of the function.

;;; Order of priority for finding file names for keys, etc:
;;; 1) If user has defined file name variables (i.e. in a .emacs file)
;;; 2) If user has defined environment variables
;;; 3) Defaults

(defvar ripem-public-key-file
  (let ((name (getenv "RIPEM_PUBLIC_KEY_FILE")))
    (if (null name)
        "/usr/local/etc/rpubkeys"
      name))
  "Name of file containing public keys for RIPEM")

(defvar ripem-secret-key-file
  (let ((name (getenv "RIPEM_PRIVATE_KEY_FILE")))
    (if (null name)
        "~/.ripemprv"
          name))
  "Name of file containing secrect keys for RIPEM")

(defvar ripem-generated-pub-key-file "~/.ripempub"
  "Name of file into which to deposit newly-created public key")

(defvar ripem-program-name "ripem")
  
  
(defun ripem-sign (&optional clear)
  "Use this to replace the contents of your mail message buffer with a signed
  mail message, preserving the mail header.  Prefix arg means sign cleartext.
  If there is any error, use UNDO (i.e. type \\[undo])."
  (interactive "P")
  (open-after-mail-delimiter)
  (ripem-process-region (point-min)
                        (point-max)
                        t
                        "-e" "-m"
                        (if clear "mic-clear" "mic-only")
                        "-h" "p"))

(defun ripem-encrypt ()
  "Use this to replace the contents of your mail message buffer with an
encrypted mail message, preserving the mail header and encrypting for each
of the recipients in the To: and cc: fields.  These must be the full user
names as they appear in the public key file, such as alice@chirality.rsa.com.
See ripem-list-users.
You must enter your private key password and a string of random bytes (for
generating a fresh encryption key).   Then simply send the message as usual.
If there is any error, use UNDO (e.g. type \\[undo])"
  (interactive)
  (open-after-mail-delimiter)
  (let ((bytes (read-n-chars-no-echo
                "Enter %d random characters for encryption key" 16)))
    (ripem-process-region (point-min)
                          (point-max)
                          t
                          "-e"
                          "-m" "encrypted"
                          "-T" "am"
                          "-h" "pr"
                          "-R" "sc"
                          "-Y" "fsg"
                          "-C" bytes)))


(defun ripem-receive ()
  "Use this to decode the privacy enhanced message in the current buffer,
or to check signatures."
  (interactive)
  (save-excursion
    (let ((end (if (re-search-forward "END PRIVACY-ENHANCED MESSAGE-----$"
                                      (point-max) t)
                   (match-end 0)
                 nil))
          (begin (if (re-search-backward "^-----BEGIN PRIV" (point-min) t)
                     (max (point-min)
                          (- (match-beginning 0) 1))
                   nil)))
      (if (or (null begin) (null end))
          (if (y-or-n-p "Can't find headers; try to do whole buffer?")
              (setq begin (point-min)
                    end (point-max))
            (error "Couldn't find PEM headers in buffer")))
      ;; Go to beginning of buffer to search for ENCRYPTED string
      (goto-char (point-min))
      (cond ((re-search-forward "2001,ENCRYPTED" (point-max) t)
             ;; Found ENCRYPTED string, so ask user for password
             (ripem-process-region begin end t "-d"))
            (t       ;; else receive as non-encrypted message
             (ripem-process-region begin end nil "-d"))))))
              



(defun ripem-process-region (start end get-password-p &rest addl-args)
  "Copies the current region to a temp buffer. If GET-PASSWORD-P
   is non-nil then prompt for the secret key password.
   Calls ripem, taking care of some housekeeping.
   Substitutes ripem's output for the current contents of region"
  (let ((my-buffer (get-buffer-create " ripem-temp"))
        (oldbuf (current-buffer)))
    (save-excursion
      (set-buffer my-buffer)
      (erase-buffer)
      (buffer-flush-undo my-buffer)
      (cond ((not (null get-password-p))
             (insert (read-string-no-echo "Enter password to private key: "))
             (newline)))
      (insert-buffer-substring oldbuf start end)
      (message "Running ripem ...")
      (apply 'call-process-region
             (point-min)
             (point-max)
             ripem-program-name
             t
             t
             nil
             "-p" (expand-file-name ripem-public-key-file)
             "-s" (expand-file-name ripem-secret-key-file)
             "-k" "-"
             addl-args))
    (goto-char start)
    (delete-region start end)
    (insert-buffer my-buffer))
  (message "Running ripem ... done."))


(defun open-after-mail-delimiter ()
  "Ensure that there is an open line after the --text follows this line--
  delimiter in the mail buffer so that RIPEM will find the body."
  (goto-char (point-min))
  (and (re-search-forward "^--text follows this line--
." (point-max) t)
       ;; found a char on the beginning of the line which should be blank,
       ;;   so back up and insert a newline before it
       (goto-char (1- (point)))
       (insert "\n")))

(defun ripem-list-users ()
  "Show all the user names which can be used as recipients in ripem-encrypt or
  for verifying signatures in ripem-receive."
  (interactive)
  (shell-command (format "grep User: %s" (expand-file-name ripem-public-key-file))))



(defun ripem-generate ()
  "Generates key files using the default user name.
You must enter your private key password and a long string of random bytes
  (for generating the keys).
Your username will have your full host name, such as alice@chirality.rsa.com.
  (If you want a different username, set up your RIPEM_USER_NAME environment
   variable and then generate.)
When done, append your new public key to the public key file.  After this,
  your new public key is no longer used directly, but you can send it to others.
Also, archive your private key file and don't forget your password!"
  (interactive)
  (let ((password (read-string-no-echo
		   "Enter password for private key (and don't forget it): " t))
	;; get 512 bits of random data, assuming 4 usable bits per char
	(random-chars (read-n-chars-no-echo
		       "Enter %d random characters for generating keys" 128))
        (buffer (get-buffer-create " ripem-temp")))
    (save-excursion
      (set-buffer buffer)
      (erase-buffer)
      (buffer-flush-undo buffer)
      (insert password)
      (newline)
      (message "Generating ...")
      (call-process-region (point-min) (point-max) ripem-program-name
                           t t t
                           "-g"
                           "-S" (expand-file-name ripem-secret-key-file)
                           "-P" (expand-file-name ripem-generated-pub-key-file)
                           "-k" "-"
                           "-R" "sc"
                           "-D 1"
                           "-C" random-chars)
      (newline)
      (insert (format "***** You must now archive %s"
                       ripem-secret-key-file))
      (newline)
      (insert (format "***** And append %s to %s"
                       ripem-generated-pub-key-file
                       ripem-public-key-file))
      (newline))
    (display-buffer buffer)
    (message "Generating. .. done.")))

(defun read-string-no-echo (prompt &optional confirm)
  "Read a string from the minibuffer, prompting with PROMPT.
Optional second argument CONFIRM non-nil means that the user will be asked
  to type the string a second time for confirmation and if there is a
  mismatch, the process is repeated.

Line editing keys are:
  C-h, DEL      rubout
  C-u, C-x      line kill
  C-q, C-v      literal next"
  (catch 'return-value
    (save-excursion
      (let ((input-buffer (get-buffer-create " *password*"))
            (cursor-in-echo-area t)
            (echo-keystrokes 0)
            char string help-form done kill-ring)
        (set-buffer input-buffer)
        (unwind-protect
            (while t
              (erase-buffer)
              (message prompt)
              (while (not (memq (setq char (read-char)) '(?\C-m ?\C-j)))
                (if (setq form
                          (cdr
                           (assq char
                                 '((?\C-h . (delete-char -1))
                                   (?\C-? . (delete-char -1))
                                   (?\C-u . (delete-region 1 (point)))
                                   (?\C-x . (delete-region 1 (point)))
                                   (?\C-q . (quoted-insert 1))
                                   (?\C-v . (quoted-insert 1))))))
                    (condition-case error-data
                        (eval form)
                      (error t))
                  (insert char))
                (message prompt))
              (cond ((and confirm string)
                     (cond ((not (string= string (buffer-string)))
                            (message
                             (concat prompt "[Mismatch... try again.]"))
                            (ding)
                            (sit-for 2)
                            (setq string nil))
			   ((string= string "")
                            (message
                             (concat prompt
				     "[String cannot be empty... try again.]"))
                            (ding)
                            (sit-for 2)
                            (setq string nil))
                           (t (throw 'return-value string))))
                    (confirm
                     (setq string (buffer-string))
                     (message (concat prompt "[Retype to confirm...]"))
                     (sit-for 2))
                    (t (throw 'return-value (buffer-string)))))
          (message (concat prompt "[Thank you!]"))
          (set-buffer-modified-p nil)
          (kill-buffer input-buffer))))))

(defun read-n-chars-no-echo (prompt n)
  "Display prompt and return a string of n characters, without echoing.
If prompt has %d in it, the countdown from n is printed there.
After n chars have been read, this still adds them to the string, and
  this waits for the user to hit enter."
  (let ((echo-keystrokes 0)
	(string "")
	(count n)
	char)
    (while (> count 0)
      (message prompt count)
      (setq string (concat string (list (read-char))))
      (setq count (1- count)))
    (while (progn
	     (message "Hit ENTER when done")
	     (not (or (= (setq char (read-char)) 13) (= char 10))))
      (setq string (concat string (list char))))
    (message "Hit ENTER when done [Thank you!]")    
    string))




