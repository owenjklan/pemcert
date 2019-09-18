from sublime import message_dialog, status_message
from subprocess import Popen, PIPE
from tempfile import mkstemp
from os import unlink, write

from sublime import Region

import sublime_plugin


def get_cert_subject_cn(decoded_cert):
    """
    Expects decoded_cert to be the output of a call to the OpenSSL
    command line utility. Already decoded to be a 'str'.
    """
    for line in decoded_cert.splitlines():
        if "Subject: " in line:
            parts = line.split('CN')
            cn = parts[1].split('=')[1].strip()
            return cn
    return None


class DecodePemCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        pem_cert = self.view.substr(Region(0, self.view.size()))
        self.decode_pem(pem_cert, edit)

    def decode_pem(self, pem_text, edit):
        temp_pem_fd, temp_pem_path = mkstemp()

        write(temp_pem_fd, bytes(pem_text, 'utf-8'))

        cmd = [
            "/usr/bin/openssl",
            "x509",
            "-in", temp_pem_path,
            "-noout",
            "-text",
        ]

        try:
            openssl_proc = Popen(cmd, stderr=PIPE, stdout=PIPE, shell=False)
            stdout, stderr = openssl_proc.communicate()
            return_code = openssl_proc.returncode

            stdout = stdout.decode()
            stderr = stderr.decode()

            if return_code != 0:
                message_dialog(stderr)
                status_message("Error during certificate decode!")
                return

            cert_cn = get_cert_subject_cn(stdout)
            if cert_cn:
                self.view.set_name(cert_cn)
            self.view.replace(edit, Region(0, self.view.size()), stdout)
        except Exception as e:
            print("Exception: {}".format(e))
        finally:
            unlink(temp_pem_path)


class CleanUpPemCommand(sublime_plugin.TextCommand):
    def run(self, edit):
        content = self.view.substr(Region(0, self.view.size()))
        # Split any escaped newline characters
        output = content.replace('\\n', '\n')
        output_lines = [line.strip() for line in output.splitlines()]
        output_text = "\n".join(output_lines)

        self.view.replace(edit, Region(0, self.view.size()), output_text)
