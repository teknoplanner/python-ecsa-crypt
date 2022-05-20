from os import abort
from flask import Flask, render_template, request, redirect, url_for, make_response
import secrets
import random
from flaskext.mysql import MySQL
import pymysql
import hashlib
from flask_recaptcha import ReCaptcha
import re
from datetime import timedelta, datetime
from flask import session, app
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_paranoid import Paranoid
from flask_paginate import Pagination, get_page_parameter
from flask_qrcode import QRcode
from pymysql import cursors
import os
from flask_uploads import IMAGES, UploadSet, configure_uploads
import pdfkit
from service import alphabet, acak, angka
