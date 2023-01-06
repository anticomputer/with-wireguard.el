;;; with-wireguard.el --- namespaced wireguard management -*- lexical-binding: t -*-

;; This is free and unencumbered software released into the public domain.

;; Author: Bas Alberts <bas@anti.computer>
;; URL: https://github.com/anticomputer/with-wireguard.el

;; Version: 0.2.0-pre
;; Package-Requires: ((emacs "25") (cl-lib "0.5"))

;; Keywords: comm

;;; Commentary

;; with-wireguard.el provides primitives for managing a wireguard vpn
;; inside a dedicated network namespace, this is useful to e.g. spawn
;; a browser or terminal that requires access to certain network
;; resources, without affecting any routing on main network namespace

;; It is compatible with wg-quick style configuration files.

;; Tips and Tricks

;; If this misbehaves on your system you likely need:
;;
;; (connection-local-set-profile-variables
;;  'remote-without-auth-sources '((auth-sources . nil)))
;;
;; (connection-local-set-profiles
;;  '(:application tramp) 'remote-without-auth-sources)
;;
;; In your TRAMP configuration, to prevent local sudo timeouts.

;; Disclaimer

;; This is experimental software written for my personal use and subject
;; to heavy feature iteration, use at your own discretion

;;; Code
(eval-when-compile (require 'subr-x))
(eval-when-compile (require 'cl-lib))

;; only use this for safety critical commands
(defun with-wg--assert-shell-command (cmd buffer)
  "Assert that a 'shell-command' CMD did not return error."
  (cl-assert (equal 0 (shell-command cmd buffer)) t
             (format "Error executing: %s" cmd)))

(defvar-local with-wg--deflate-ns-on-process-exit nil)
(defvar-local with-wg--buffer-namespace nil)

(defun with-wg--sudo-process (name buffer &rest args)
  "Sudo exec a command ARGS as NAME and output to BUFFER.

Only use this for long lived processes that need state awareness."
  ;; in case we want to juggle any buffer local state
  (with-current-buffer buffer
    (message "Executing: %s" args)
    (let* ((tramp-connection-properties '((nil "session-timeout" nil)))
           (default-directory "/sudo:root@localhost:/tmp")
           (process (apply #'start-file-process name buffer args)))
      (when (process-live-p process)
        (set-process-sentinel
         process (lambda (proc event)
                   (unless (process-live-p proc)
                     (with-current-buffer (process-buffer proc)
                       (when (and with-wg--deflate-ns-on-process-exit
                                  with-wg--buffer-namespace)
                         (message "Process exited, auto-deflating namespace %s" with-wg--buffer-namespace)
                         (with-wg--deflate-ns with-wg--buffer-namespace))))))
        (set-process-filter
         process (lambda (_proc string)
                   (mapc 'message (split-string string "\n"))))))))

(defun with-wg--sudo-shell-command (cmd buffer)
  "Sudo exec a shell command CMD and output to BUFFER."
  ;; in case we want to juggle any buffer local state
  (with-current-buffer buffer
    (message "Executing: %s" cmd)
    (let* ((tramp-connection-properties '((nil "session-timeout" nil)))
           (default-directory "/sudo:root@localhost:/tmp"))
      (with-wg--assert-shell-command cmd buffer))))

(defun with-wg-quick-conf (config)
  "Pull Address and DNS from wg-quick CONFIG.
Returns a setconf compatible configuration."
  (with-temp-buffer
    (insert-file-contents-literally (expand-file-name config) nil)
    (let
        ((lines
          (cl-loop while (not (eobp))
                   collect
                   (prog1 (buffer-substring-no-properties
                           (line-beginning-position)
                           (line-end-position))
                     (forward-line 1)))))
      (let ((conf (make-temp-file "wg"))
            (dns-conf (make-temp-file "ns"))
            (addresses)
            (nameservers)
            (search))
        ;; write our setconf conf
        (with-temp-file conf
          (cl-loop for line in lines
                   do
                   ;; filter any crud that's not setconf compatible, grab what we need
                   (cond ((string-match "^ *Address *= *\\(.*\\)? *\n*" line)
                          (let ((address (match-string 1 line)))
                            (if (string-match-p "," address)
                                (setq addresses (append addresses (split-string address ",")))
                              (setq addresses (append addresses (list address))))))
                         ;; XXX: these can have multiple entries too, similar to addresses
                         ((string-match "^ *DNS *= *\\(.*\\)? *\n*" line)
                          (let* ((dns (match-string 1 line))
                                 (entries (if (string-match-p "," dns)
                                              (split-string dns ",")
                                            (list dns))))
                            (cl-loop for entry in entries do
                                     (cond ((string-match-p "[a-zA-Z]" entry)
                                            (setq search (cons entry search)))
                                           (t (setq nameservers (cons entry nameservers)))))))
                         ;; skip comments
                         ((string-match-p "^#" line))
                         ;; TODO: implement all these ... I guess
                         ((string-match-p "^ *\\(?:MTU\\|Table\\|Table\\|PreUp\\|PostUp\\|PreDown\\|PostDown\\|SaveConfig\\)" line))
                         (t (insert (concat line "\n"))))))
        ;; write our resolv conf
        (with-temp-file dns-conf
          (when search
            (insert (concat "search " (string-join search " ") "\n")))
          (when nameservers
            (cl-loop for ns in nameservers do
                     (insert (format "nameserver %s\n" ns)))))
        ;; return conf, address, dns
        (list conf addresses (when (or search nameservers) dns-conf))))))

;; XXX: TODO make this create a /etc/netns/namespace/resolv.conf if dns is set
(defun with-wg--inflate-ns (config &optional addresses dns)
  "Create a namespace for wireguard CONFIG.

Optionally, override CONFIG with a list of ADDRESSES and DNS."
  (cl-destructuring-bind (tmp-config conf-addresses conf-dns) (with-wg-quick-conf config)
    ;; allow user to override if they want, default to quick conf compatibility
    (let* ((addresses (or addresses conf-addresses))
           (dns (or dns conf-dns))
           (interface (make-temp-name "if"))
           (namespace (make-temp-name "ns"))
           (procbuf (get-buffer-create (format " *with-wireguard-%s*" namespace)))
           ;; deal with systems where root might not have these in PATH
           (ip (executable-find "ip"))
           (wg (executable-find "wg"))
           (inflate-cmds
            (append
             `((,ip "netns" "add" ,namespace)
               (,ip "link" "add" ,interface "type" "wireguard")
               (,ip "link" "set" ,interface "netns" ,namespace))
             ;; interface can have multiple addresses out of configuration
             (cl-loop for address in addresses collect
                      (list ip "-n" namespace "addr" "add" address "dev" interface))
             `((,ip "netns" "exec" ,namespace ,wg "setconf" ,interface ,tmp-config)
               (,ip "-n" ,namespace "link" "set" ,interface "up")
               (,ip "-n" ,namespace "route" "add" "default" "dev" ,interface))
             (when dns
               `(("/bin/sh" "-c"
                  ,(format "\"mkdir /etc/netns/%s && mv %s /etc/netns/%s/resolv.conf\""
                           namespace dns namespace)))))))
      (cl-loop for args in inflate-cmds
               for cmd = (string-join args " ")
               do (with-wg--sudo-shell-command cmd procbuf))
      ;; delete the temporary config copy
      (delete-file tmp-config)
      ;; set the namespace in the proc buffer
      (with-current-buffer procbuf
        (setq with-wg--buffer-namespace namespace))
      ;; return the namespace
      namespace)))

(defun with-wg--deflate-ns (namespace)
  "Delete wireguard NAMESPACE."
  (cl-assert (not (string-match-p "[./]" namespace)))
  (let* ((procbuf (get-buffer-create (format " *with-wireguard-%s*" namespace)))
         (ip (executable-find "ip"))
         ;; keep this as a list in case we want to add additional teardowns
         ;; e.g. (,ip "-n" ,namespace "link" "set" ,interface "down")
         (deflate-cmds
           `((,ip "netns" "delete" ,namespace)
             ("rm" "-rf"
              ,(format "/etc/netns/%s"
                       ;; this should never be needed, but just in case
                       (shell-quote-argument namespace))))))
    (cl-loop for args in deflate-cmds
             for cmd = (string-join args " ")
             do (with-wg--sudo-shell-command cmd procbuf))
    (kill-buffer procbuf)))

(defun with-wg-shell-command (cmd namespace &optional auto-deflate-ns user)
  "Run shell command CMD in NAMESPACE.

Optionally AUTO-DEFLATE-NS on exit of the command &| run with USER privileges.

CMD will be double quoted as an argument to /bin/sh -c, but does not receive
other treatment. The user is expected to be aware of any caveats and ensure
they do not accidentally misquote or otherwise escape the argument.

These commands run with sudo privileges, so tread carefully."
  (let ((user (or user (user-real-login-name)))
        (procbuf (get-buffer-create (format " *with-wireguard-%s*" namespace))))
    ;; set deflate flag for process sentinel
    (with-current-buffer procbuf
      (setq with-wg--deflate-ns-on-process-exit auto-deflate-ns))
    (with-wg--sudo-process
     "wg: exec" procbuf
     "/bin/sh" "-c"
     ;; careful here, easy to shoot yourself in the foot
     ;; we do not shell quote command so it is up to you
     ;; to ensure you're staying in the correct context
     (format "ip netns exec %s sudo -u %s /bin/sh -c \"%s\""
             namespace user cmd))))

;; this expects lexical-binding to be t
(cl-defmacro with-wg ((config) ns &body body)
  "Evaluate BODY with WIREGUARD-CONFIG with symbol NS bound to active namespace."
  `(let ((,ns (with-wg--inflate-ns (expand-file-name ,config))))
     ,@body))

;;;###autoload
(defun with-wg-execute (config cmd &optional auto-deflate-ns)
  "Execute shell command CMD in a network namespace for wireguard CONFIG."
  (interactive "fWireguard config: \nsShell command: ")
  (with-wg (config) namespace
           ;; by default we deflate the ns when this command exits
           (with-wg-shell-command cmd namespace auto-deflate-ns)))

(provide 'with-wireguard)
;;; with-wireguard.el ends here
