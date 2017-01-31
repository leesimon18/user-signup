#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import cgi
import fnmatch
import re

form="""
<form method="post">
    <font size="20px"><b>Signup</b></font>
    </br>
    </br>
    <table style="font-weight:bold">
        <tr>
            <td align="right">Username</td>
            <td align="right"><input style="width:160px;" name="user_name" value="%(user_uname)s"/></td>
            <td align="left" style="color: red">%(uname_error)s</td>
        </tr>
        <tr>
            <td align="right">Password</td>
            <td align="right"><input style="width:160px;" type="password" name="pw" value=""/></td>
            <td align="left" style="color: red">%(user_pw_error)s</td>
        </tr>
        <tr>
            <td align="right">Verify Password</td>
            <td align="right"><input style="width:160px;" type="password" name="verify_pw" value=""/></td>
            <td align="left" style="color: red">%(verify_pw_error)s</td>
        </tr>
        <tr>
            <td align="right">Email (optional)</td>
            <td align="right"><input style="width:160px;" name="email" value="%(user_email)s"/></td>
            <td align="left" style="color: red">%(verify_email_error)s</td>
        </tr>
    </table>
    </br>

    <input type="submit" name="submit" value="Submit">
</form>
"""

# --- Valid User Name
def valid_uname(user_uname):
    if user_uname is None:
        user_uname = "Please enter in a user name."
        return user_uname

def escape_html(s):
    return cgi.escape(s, quote=True)


uname_check = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
pw_check = re.compile(r"^.{3,20}$")
email_check = re.compile(r"^[\S]+@[\S]+.[\S]+$")


class MainHandler(webapp2.RequestHandler):
    def write_form(self, uname_error="", user_pw_error="", verify_pw_error="", verify_email_error="",
                   user_uname="", user_email=""):
        self.response.out.write(form % {"uname_error": uname_error,
                                        "user_pw_error": user_pw_error,
                                        "verify_pw_error": verify_pw_error,
                                        "verify_email_error": verify_email_error,

                                        "user_uname": escape_html(user_uname),
                                        "user_email": escape_html(user_email)
                                        })

    def get(self):
        self.write_form()

    def post(self):
        user_uname = self.request.get('user_name')
        user_pw = self.request.get('pw')
        user_verify_pw = self.request.get('verify_pw')
        user_email = self.request.get('email')

        email_check = "*@*.*"
        error_check = False
        if not (user_uname and uname_check.match(user_uname)):
            uname_error = "Please enter a valid user name"
            error_check = True
        else:
            uname_error = ""
        if not (user_pw and pw_check.match(user_pw)):
            user_pw_error = "Please enter a valid password"
            error_check = True
        else:
            user_pw_error = ""
        if user_pw != user_verify_pw and (not user_pw or not user_verify_pw):
            verify_pw_error = "Passwords do not match"
            error_check = True
        else:
            verify_pw_error = ""
        if user_email != "" and not fnmatch.fnmatch(user_email, email_check):
            verify_email_error = "Invalid email address"
            error_check = True
        else:
            verify_email_error = ""

        if error_check == True:
             self.write_form(uname_error, user_pw_error, verify_pw_error, verify_email_error,
                             user_uname, user_email)
        else:
            self.redirect("/welcome?user_name=" + user_uname)

class Welcome(webapp2.RequestHandler):
    def get(self):
        user_uname = escape_html(self.request.get('user_name'))
        self.response.write("<h1>Welcome, " + user_uname + "!</h1>")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome', Welcome),
], debug=True)
