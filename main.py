import base64
import binascii
import datetime
import decimal
import hashlib
import http
import http.client
import io
import itertools
import json
import logging as logger
import os
import random
import re
import string
import uuid
from collections import Counter
from functools import reduce
from hashlib import md5
from itertools import groupby
from operator import itemgetter, add
from string import Template
from threading import Thread
from time import time

# load environment variables
from dotenv import load_dotenv

load_dotenv()

import boto3
import cx_Oracle
import dpath.util
import dpath.util
import pandas as pd
import pdfkit
import requests as req
from urllib.request import urlopen
from Cryptodome.Cipher import AES
from PIL import Image
from configparser import ConfigParser
from flask import abort, jsonify, request, redirect, send_from_directory
from flask.ctx import copy_current_request_context
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token, get_jwt_identity, jwt_required, jwt_refresh_token_required,jwt_optional
)
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename

from app import app
from cibil import CIBIL
from custom_utils import redis as redis_obj
from custom_utils.sqs import SQSHandler
from custom_utils.utility import alert_chat_app, error_alert, convert_keys_to_lowercase
from custom_utils.cerbos import _check_access,cerbos_resource_manager, _get_roles
from eligibility_excel_parsing import parse_and_save_scorecard_excel_sheet, get_scorecard_data_from_tables, \
    rollback_erred_scorecard_data, set_latest_flag
from external import ExternalApi
from type_handler import TypeHandler
from msg91_response_handler import validate_msg91_response
from mydb import Database, dbConfig, LMS
from mydb.database import engine
from s3fileupload import S3FILEUPLOAD
from pytz import timezone
from babel.numbers import format_currency
from functools import wraps
# S3FILEUPLOAD object
_s3fileupload = S3FILEUPLOAD()
ENVIRONMENT = os.getenv('ENVIRONMENT')
sqs_object = SQSHandler(queue_url = os.getenv('SQS_QUEUE_URL'), queue_name = os.getenv('SQS_QUERY_NAME'), target = 'LMS', environment = ENVIRONMENT)
query_parser = ConfigParser()
error_parser = ConfigParser()
app_config_parser = ConfigParser()
query_parser.read('./mydb/queries.config')
error_parser.read('./mydb/error.config')
app_config_parser.read('./application.config')

mail_config = {
    "MAIL_SERVER": 'smtp.gmail.com',
    "MAIL_PORT": 465,
    "MAIL_USE_TLS": False,
    "MAIL_USE_SSL": True,
    "MAIL_USERNAME": os.getenv('EMAIL_USER'),
    "MAIL_PASSWORD": os.getenv('EMAIL_PASSWORD')
}

ALLOWED_KYC_NAMES = {'profile_image_url': 1, 'gst_file_url': 2, 'pan_file_url': 2, 'aadhar_f_file_url': 3,
                     'aadhar_b_file_url': 3}
_wkhtml_config = pdfkit.configuration(wkhtmltopdf=os.getenv('WKHTML_CONFIG'))
report_recipients = os.getenv('LOAN_REPORT_EMAIL_LIST').split(",")
recipients = os.getenv('LOAN_APPLICATION_EMAIL_LIST').split(",")
carbon_copy_list = os.getenv('FASTAG_CC_LIST').split(",")
alert_recipients = os.getenv('SYSTEM_ALERT_EMAIL_LIST').split(",")
transporter_docs_bucket = os.getenv('TRANSPORTER_DOCS_BUCKET')
dealership_docs_bucket = os.getenv('DEALERSHIP_DOCS_BUCKET')
docs_url = os.getenv('DOCS_URL')

ALLOWED_DOC_EXTENSIONS = app_config_parser.get('file_type', 'allowed_doc_extension').split(",")
ALLOWED_MEDIA_EXTENSIONS = app_config_parser.get('file_type', 'allowed_media_extension').split(",")
EXTERNAL_DASHBOARD_ROLE_ACCESS_LIST = app_config_parser.get('external_dashboard',
                                                            'vivriti_dashboard_access_roles').split(",")
POTENTIAL_OPPORTUNITIES_ROLE_ACCESS_LIST = app_config_parser.get('potential_opportunities',
                                                                 'potential_opportunities_access_roles').split(",")
USER_MAINAPPLICANT_FIELDS = app_config_parser.get('user_mainapplicant', 'user_mainapplicant_mandatory_fields').split(",")
REPAYMENT_FIELDS = app_config_parser.get('repayment', 'repayment_mandatory_fields').split(",")
SMS_API_AUTH_KEY = '293004Af9qkN64BTm85d736ebe'
OTP_TEMPLATE = '5e60da24d6fc0535104160ac'
LEEGALITY_URL = os.getenv('LEEGALITY_URL')
LEEGALITY_AUTH_TOKEN = os.getenv('LEEGALITY_AUTH_TOKEN')
LEEGALITY_WEB_HOOK = os.getenv('LEEGALITY_WEB_HOOK')
CRYPT_FE_KEY = os.getenv('CRYPT_FE_KEY')
CRYPT_BE_KEY = os.getenv('CRYPT_BE_KEY')
SECURE_DATA = os.getenv("DATA_TO_ENCRYPT").split(',')
BLOCK_SIZE = os.getenv("ENCRYPTION_BLOCK_SIZE")
ORACLE_URI = os.getenv("ORACLE_URI")

# Declaring constants
ADMIN_ROLE_ID = 1
OTHER_DOCUMENTS_ID = 17

content_type_map = {
    "pdf": "application/pdf",
    "csv": "text/csv",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "xls": "application/vnd.ms-excel",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "json": "application/json",
    "mp3": "audio/mp3",
    "m4a": "audio/m4a"
}

options = {
    'page-size': 'A4',
    'margin-top': '0.9in',
    'margin-right': '0.5in',
    'margin-bottom': '1.5in',
    'margin-left': '0.5in',
    'encoding': "UTF-8",
    'footer-html': 'template/footer.html',
    'custom-header': [
        ('Accept-Encoding', 'gzip')
    ],
    'cookie': [
        ('cookie-name1', 'cookie-value1'),
        ('cookie-name2', 'cookie-value2'),
    ],
    'no-outline': None,
    'enable-local-file-access': None
}

# database is using values from .env file this import should be after the load env
logger.basicConfig(level='DEBUG')

# database object
mydb = Database(dbConfig())
lms_db = Database(LMS())

# Datatype handler object
validate = TypeHandler()

# external_api object
bridge = ExternalApi()

# cibil object
_cibil = CIBIL()

app.config['PROJECT_DIR'] = os.getcwd()
app.config['UPLOAD_FOLDER'] = "data"
app.config['TEMPLATE_DIR'] = app.config['PROJECT_DIR'] + "/template"
app.config['APPLICATION_TEMPLATE'] = app.config['TEMPLATE_DIR'] + "/application.html"
app.config['SANCTION_LETTER_TEMPLATE'] = app.config['TEMPLATE_DIR'] + "/sanction_letter.html"
app.config['NOC_CLOSED_LETTER_TEMPLATE'] = app.config['TEMPLATE_DIR'] + "/noc_closed.html"
app.config['NOC_OPEN_LETTER_TEMPLATE'] = app.config['TEMPLATE_DIR'] + "/noc_open.html"
app.config['EXPERIAN_TEMPLATE'] = app.config['TEMPLATE_DIR'] + "/experian-cons-req-template.xml"
app.config['PDR_TEMPLATE'] = app.config['TEMPLATE_DIR'] + "/pdr-report.html"
app.config['TARGET_FILE_PATH'] = app.config['PROJECT_DIR'] + "/" + app.config['UPLOAD_FOLDER']
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

_support_message = "Contact support at "+os.getenv('GENERAL_SUPPORT')+"."

# Configure application to store JWTs in cookies. Whenever you make
# a request to a protected endpoint, you will need to send in the
# access or refresh JWT via a cookie.
# app.config['JWT_TOKEN_LOCATION'] = ['cookies']

# Only allow JWT cookies to be sent over https.
# In production, this should likely be True
# app.config['JWT_COOKIE_SECURE'] = False

# Set the cookie paths, so that you are only sending your access token
# cookie to the access endpoints, and only sending your refresh token
# to the refresh endpoint. Technically this is optional, but it is in
# your best interest to not send additional cookies in the request if
# they aren't needed.
app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/login/check'

# Enable csrf double submit protection. See this for a thorough
# explanation: http://www.redotheweb.com/2015/11/09/api-security.html
# app.config['JWT_COOKIE_CSRF_PROTECT'] = False

# JWT secret - Set the secret key to sign the JWTs with
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')
# s3 Role ARN
app.config['S3_ROLE_ARN'] = os.getenv('ROLE_ARN')

jwt = JWTManager(app)

@jwt_optional
def authorization():
    if not request.url_rule: #If flask couldn't return the url it must be 404/405.
        return jsonify({"status":"ERROR","message":"404 not found"}),404
    if request.method != 'OPTIONS':
        user_id = get_jwt_identity()
        action = 'edit'
        if request.method == 'GET':
            action = 'read'
        elif request.method == 'DELETE':
            action = 'delete'
        if user_id:
            role_name = _get_result_as_dict(query=query_parser.get('rbac','_get_role_name_by_user_id').format(user_id))[0].get('role_name')
            resource_details = _get_result_as_dict(query_parser.get('rbac','_get_resource_name_by_route').format(request.url_rule))[0]
            resources = [
                  {
                      "actions": [
                          action
                      ],
                      "resource": {
                          "kind": resource_details.get('resource'),
                          "id": str(resource_details.get('resource_id'))
                      }
                  }]
            response = _check_access(user_id = user_id, roles = [role_name], resources = resources)
            if not response.get('results')[0].get('actions').get(action) == 'EFFECT_ALLOW':
                logger.error("Unauthorized request {}".format(response))
                if ENVIRONMENT == "PROD":
                    alert_chat_app(os.getenv('ACTIVE_CHAT_APP_TO_NOTIFY'), f"Unauthorized request to PROD \n user_id -> {user_id} \n role -> {role_name} \n API Route -> {request.url_rule} \n Resource -> {resources} \n DeviceType -> {'Mobile (App)' if request.headers.get('Ismobile') else 'MDM or Portal'}") # We have to review the unauthorized requests for couple of weeks.
                return jsonify({"status":"ERROR","message":"Unauthorized request."}),403


@app.before_request
def _before_request():
    if request.endpoint not in os.getenv('RBAC_EXCEPTION_LIST').split(','):
        response = authorization()
        if response:
            return response


@app.route('/api/user/access',methods=['GET'])
@jwt_required
def user_access():
    user_id = str(get_jwt_identity())
    roles = [role.get('role_name') for role in _get_result_as_dict(query = query_parser.get('rbac','_get_role_name_by_user_id').format(user_id))]
    resources = [json.loads(resource.get('resource')) for resource in _get_result_as_dict(query_parser.get('rbac','_get_resources_and_action').format(request.args.get('type','MDM')))]
    return _check_access(user_id = user_id, roles = roles, resources = resources)


@app.route('/api/rbac/resource',methods=['GET','POST'])
@app.route('/api/rbac/resource/<int:resource_id>',methods=['PUT','GET'])
@app.route('/api/rbac/action/<int:action_id>',methods = ['PUT'])
@jwt_required
def get_resource(resource_id=None,action_id = None):
    if request.method == 'GET':
        column_name_in_where_condition,value = 'type',request.args.get('type')
        if resource_id:
            column_name_in_where_condition,value = 'id',resource_id
        return jsonify({'status':'SUCCESS','data':_get_result_as_dict(query_parser.get('rbac','_get_resourse_by_dynamic_column_name').format(column_name_in_where_condition,value))})
    data = request.get_json()
    if request.method == 'POST':
        resource_type = data.get('type')
        query = query_parser.get('rbac','_insert_resources')
        records = []
        for resource in data.get('resources'):
            records.append((resource_type,resource.get('resource'),resource.get('description')))
        if len(records) == 1:
            return _execute_query(query_type=mydb.INSERT,query=query % records[0],success_message = 'Resource added successfully',fail_message = 'Resource already exists')
        else:
            mydb._bulk_insert(query = query, records = records)
            return jsonify({'status':'SUCCESS','message':'Resources added successfully.'})
    elif request.method == 'PUT':
        if resource_id:
            actions = []
            for action in data.get('actions'):
                action.update({'resource_id':resource_id,'allowed_roles':_get_roles(role_names = action.get('allowed_roles'))})
                actions.append(action)
            _existing_actions = [{**i,'allowed_roles':i.get('allowed_roles').split(',')} for i in _get_result_as_dict(query=query_parser.get('rbac','_get_actions_by_resource_id').format(resource_id))]
            actions.extend(_existing_actions)
            return cerbos_resource_manager(resource_name = data.get('resource_name'),actions = actions)
        else:
            return _execute_query(query_type=mydb.UPDATE,query=mydb._gen_update_query(table_name = 't_cerbos_action',columns = ['description'],data = data) + " WHERE id = {}".format(action_id))


@app.route('/api/role/<int:role_id>/access',methods=['GET','PUT'])
@jwt_required
def user_access_by_id(role_id=None):
    if request.method == 'GET':
        return jsonify(status='SUCCESS',data=[json.loads(i.get('rbac')) for i in _get_result_as_dict(query_parser.get('rbac','_get_user_access_by_id').format(role_id,request.args.get('type')))])
    elif request.method == 'PUT':
        role_id = str(role_id)
        resources = {}
        for item in request.get_json():
            resources.setdefault(item['resource_name'], []).append(item)
        for resource_name,actions in resources.items():
            query = query_parser.get('rbac','_get_actions_by_resource_id').format(actions[0].get('resource_id'))
            results = _get_result_as_dict(query)
            _existing_actions = [{**i,'allowed_roles':i.get('allowed_roles').split(',')} for i in results]
            for action in actions:
                for value in _existing_actions:
                    if value['action'] == action['action_name'] and value['resource_id'] == action['resource_id']:
                        if action['permission'] == 'EFFECT_ALLOW' and role_id not in value['allowed_roles']:
                            value['allowed_roles'].append(role_id)
                        elif action['permission'] == 'EFFECT_DENY' and role_id in value['allowed_roles']:
                            value['allowed_roles'].remove(role_id)
            cerbos_resource_manager(resource_name = resource_name,actions = _existing_actions)

        return jsonify({'status':'SUCCESS','message':'Access updated successfully.'})


# Basic API route
@app.route('/', methods=['GET'])
@app.route('/api', methods=['GET'])
def main():
    return redirect("https://www.petromoney.in", code=302)


@app.route('/data/<path:path>')
def send_data_file(path):
    return send_from_directory('data', path)


@app.route('/template/<path:path>')
def send_js(path):
    return send_from_directory('template', path)


@app.route('/api/app/version', methods=['GET'])
def _app_version():
    _version = mydb.run_query(mydb.SELECT, query_parser.get('app', '_get_app_version'))
    return jsonify({"status": "SUCCESS", "version": _version[0].get('version')})


@app.route('/api/user/agreement/<string:device_id>', methods=['GET'])
@app.route('/api/user/agreement', methods=['POST'])
def _user_agreement(device_id=None):
    if device_id:
        result = _get_result_as_dict(query_parser.get('app', '_get_user_agreement').format(device_id))
        if result:
            return jsonify({"status": "SUCCESS", "message": "User agreed the Terms.", "data": result})
        else:
            return jsonify({"status": "ERROR", "message": "Please, agree to the Terms to continue."})
    if request.method == 'POST':
        data = request.get_json()
        _agreement_data = {"device_id": data.get('device_id'),
                           "details": data.get("details")
                           }
        _query = mydb._gen_insert_query('t_user_agreement', _agreement_data)
        return _execute_query(mydb.INSERT, _query)


@app.route('/api/dealership/search', methods=['GET'])
@jwt_required
def search_dealership_id():
    keyword = request.args.get('dealership')
    _get_dealership_id = query_parser.get('dealership', '_search_dealership_id').format(keyword)
    if request.args.get('status'):
        status = str(request.args.get('status').split(',')).replace('[', '').replace(']', '')
        _get_dealership_id = query_parser.get('dealership', '_search_dealership_id_based_on_loan_status').format(
            keyword, status)
    return _get_result(_get_dealership_id)


@app.route('/api/loans/remarks', methods=['GET'])
@jwt_required
def get_remarks():
    return _get_result(query_parser.get('remarks', '_get_remarks'))


def s3_multi_file_upload(files, dealership_id):
    _upload_status = []
    file_url = {}
    attachment_count = 1
    for file in files:
        file_name = secure_filename(files.get(file).filename)
        if allowed_file(file_name) and attachment_count <= 5:
            _s3_file_prefix = str(dealership_id) + '/payment-proofs'
            _status, _uploaded_file = _s3_file_upload(_s3_file_prefix,
                                                      file_name,
                                                      dealership_docs_bucket,
                                                      files.get(file))
            _upload_status.append(_status)
            if _status:
                file_url.update({'proof_{}_url'.format(attachment_count): _uploaded_file})
                attachment_count += 1
    if all(_upload_status):
        return True, str(file_url).replace("'", '"')
    return False, None


def send_whatsapp_notification(mobile, data, template_id):
    response = _whatsapp_push_reminder(mobile, data, template_id)
    if response.get('status') == 'false':
        logger.error("Failed to send notification for {} because {}".format(mobile, json.dumps(response)))


@app.route('/api/<int:id>/crimecheck', methods=['POST', 'GET'])
@jwt_required
def _crimecheck_company(id=None):
    """ This API used to initiate the crimecheck report request for company"""
    applicant_type = str(request.args.get("type"))
    if request.method == 'POST':
        cur_date = datetime.date.today().strftime("%d-%m-%Y")
        crimecheck = mydb.run_query(mydb.SELECT, query_parser.get('crimecheck', '_check_existing_crimecheck').format(id,
                                                                                                                     applicant_type))
        if crimecheck:
            date_check = crimecheck[0].get('created_date')
            if cur_date == date_check:
                return jsonify({'status': 'SUCCESS', 'message': 'your crimecheck request already in progress.'})
        if applicant_type == 'dealer':
            _data = _get_result_as_dict(query_parser.get('crimecheck', '_get_crimecheck_dealers_details').format(id))[0]
        elif applicant_type == 'guarantor':
            _data = _get_result_as_dict(query_parser.get('crimecheck', '_get_crimecheck_guarantor_details').format(id))[
                0]
        elif applicant_type == 'coapplicant':
            _data = \
            _get_result_as_dict(query_parser.get('crimecheck', '_get_crimecheck_coapplicants_details').format(id))[0]
        elif applicant_type == 'dealership':
            _data = \
            _get_result_as_dict(query_parser.get('crimecheck', '_get_crimecheck_dealership_details').format(id))[0]
        if not _data:
            return jsonify({"status": "ERROR", "message": "No data found for the applicant"})
        if request.args.get('crimewatch'):
            _data.update({'crimewatch': 1})
        return crimecheck_integration(_data, applicant_id=id, applicant_type=applicant_type)
    if request.method == 'GET':
        crimecheck_result = mydb.run_query(mydb.SELECT,
                                           query_parser.get('crimecheck', '_get_dealers_crimecheck_report').format(id,
                                                                                                                   applicant_type))
        if not crimecheck_result:
            return jsonify({"status": "SUCCESS", "message": "couldn't find the crime check report"})
        _result = json.loads(crimecheck_result[0].get('file_data'))
        crimecheck_results = {
            'applicant_id': crimecheck_result[0].get('applicant_id'),
            'type': crimecheck_result[0].get('type'),
            'file_data': _result
        }
        return jsonify({'status': 'SUCCESS', 'data': [crimecheck_results]})


def crimecheck_integration(_data=None, applicant_id=None, applicant_type=None):
    try:
        result = bridge._crime_check(_data)
        response = result.json()
        if response.get('requestId'):
            _data.update(
                {'request_id': response.get('requestId'), 'pan': _data.get('panNumber'), 'applicant_id': applicant_id,
                 'type': applicant_type, "created_by": get_jwt_identity()})
            _cols = mydb._get_columns('t_crimecheck_report')
            _execute_query(mydb.INSERT, mydb._gen_insert_query_exclude_cols('t_crimecheck_report', _cols, _data))
            return jsonify({'status': 'SUCCESS', 'message': 'crimecheck report requested successfully.'})
    except json.decoder.JSONDecodeError:
        return jsonify({'status': "ERROR", 'message': "Couldn't handle the request please try again."})


@app.route('/api/crimecheck/callback', methods=['POST'])
def crimecheck_callback():
    """ This API used to get crimecheck report from the 3rd party API """
    try:
        data = dict(request.form)
        _data = json.loads(data.get('data'))
        logger.debug("crimecheck callback response {}".format(_data))
        requestId = _data.get('requestId') if _data.get('requestId') else _data.get('uniqueId')
        if requestId:
            _result = \
            _get_result_as_dict(query_parser.get('crimecheck', '_get_crimecheck_report_by_id').format(requestId))[0]
            """ 'downloadLink' changed into base64 content  """
            encoding = _data.get('downloadLink')
            file = base64.b64encode(urlopen(encoding).read())
            _s3_file_prefix = "dealership/" + str(requestId) + "/crimecheck"
            _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(_s3_file_prefix,
                                                                                      "{}_crimecheck.pdf".format(
                                                                                          requestId),
                                                                                      dealership_docs_bucket,
                                                                                      file)
            if _upload_status:
                _result.update({'docs_url': _uploaded_file_url})
                _execute_query(mydb.INSERT, mydb._gen_insert_query_exclude_cols('t_crimecheck_report',
                                                                                mydb._get_columns(
                                                                                    't_crimecheck_report'),
                                                                                _result))
                return jsonify({'status': 'SUCCESS', 'message': 'File received successfully'})
    except Exception as e:
        logger.debug("Invalid input error: {}".format(e))
        return jsonify({"status": "ERROR", "message": "Invalid input"})


def _gen_credit_reload_sub_query_based_on_filter(processed = None, zone = None, region = None, account_type = None, from_date = None, to_date = None, product = None, dealership_id = None,state = None, dealership_name = None, **kwargs):
    # Note: If this function is updated, please ensure that the same changes are made in the corresponding Lambda function.
    query = "SELECT request_id from t_credit_reload_history crh "
    where_conditions = [f" crh.reload_status {'<>' if processed == '1' else '='} 'In Progress' ",' (crh.account_id IS NOT NULL OR crh.bank_id is NOT NULL)']
    zone_filter = f" AND mr.zone_id in {_split(zone)} " if zone else ''
    region_filter = f" AND mr.id in {_split(region)} " if region else ''
    state_filter = f" AND mr.state_id in {_split(state)} " if state else ''
    product_filter = f" INNER JOIN t_dealership_loans tdl on md.id = tdl.dealership_id and tdl.is_current = 1 and tdl.product_id in {_split(product)} " if product else ''
    dealership_id_filter = f" AND md.id = {dealership_id} " if dealership_id else ''
    dealership_name_filter = f" AND md.name = '{dealership_name}' " if dealership_name else ''
    query+=f"INNER JOIN t_users_region_map urm ON {get_jwt_identity()} = urm.user_id INNER JOIN m_regions mr on urm.region_id = mr.id {zone_filter+region_filter+state_filter} INNER JOIN m_dealership md on md.region = mr.id and crh.dealership_id = md.id {dealership_id_filter}{dealership_name_filter}{product_filter}"
    if account_type:
        where_conditions.append(f"crh.account_id in {_split(account_type)}")
    if from_date and to_date:
        to_date = _increment_date(to_date) if from_date == to_date else to_date
        where_conditions.append(f" CAST({'crh.created_date' if processed == '1' else 'crh.modified_date'} as date) BETWEEN '{from_date}' AND '{to_date}'")
    return query + f" WHERE {' AND '.join(where_conditions)}"


@app.route('/api/credit/reload/report', methods = ['GET'])
@jwt_required
def download_credit_reload_report():
    args = dict(request.args)
    user_id = get_jwt_identity()
    processed = args.get('processed','0')
    if args.get('download'):
        result = _get_result_as_dict(_gen_credit_reload_sub_query_based_on_filter(**args) + " LIMIT 1")
        if result:
            _execute_query(mydb.UPDATE,query_parser.get('mdm_credit','_remove_old_report').format(user_id,processed)) # Soft deleting the old report
            args.update({'user_id':user_id,'processed':processed})
            _insert_view_report_query = mydb._gen_insert_query_exclude_cols('t_credit_reload_download_report',['user_id','processed'],args)
            affected_rows,request_id = mydb.run_query(mydb.INSERT,query=_insert_view_report_query,row_insert_id=True)
            args.update({'request_id': request_id, 'environment': ENVIRONMENT})
            # Invoke lambda function
            response = req.post(os.getenv('CREDIT_RELOAD_REPORT_GENERATION_LAMBDA_URL'), json=args, headers = {'x-api-key':os.getenv('CREDIT_RELOAD_REPORT_GENERATION_LAMBDA_API_KEY'),'InvocationType':'Event'})
            return jsonify({'status': 'SUCCESS', 'message': 'Report generation in progress.', 'data': []})
        return jsonify({'status': 'ERROR', 'message': 'No data found to generate report.'})
    result = _get_result_as_dict(query_parser.get('mdm_credit','_view_report').format(user_id,processed))
    if result:
        return jsonify(data = result, status = 'SUCCESS', message = result[0].get('status'))
    return jsonify(data = result, status = 'SUCCESS', message = 'No reports found')


def _is_vivriti_loan_product(crr_id = None, dealership_id = None):
    query = query_parser.get('loans_ext','_is_vivriti_loan')
    if crr_id:
        query = query.format('crh.request_id',crr_id)
    elif dealership_id:
        query = query.format('tdl.dealership_id', dealership_id)
    return _get_result_as_dict(query)


@app.route('/api/credit/reload/<int:dealership_id>', methods=['POST', 'GET'])
@app.route('/api/credit/reload/<id>', methods=['POST'])
@app.route('/api/credit/reload', methods=['GET'])
@jwt_required
def credit_reload_request(dealership_id=None, id=None):
    if request.method == 'POST':
        data = dict(request.form)
        data.update({'last_modified_by': get_jwt_identity()})
        if dealership_id:
            _check_fields_in_request_data(['amount', 'request_source', 'bank_id'], data)
            credit_reload_amount = int(float(data.get('amount')))
            if credit_reload_amount < 50000 or credit_reload_amount > 3000000:
                return jsonify({"status": "ERROR", "message": "Please enter a valid amount between 50000 and 3000000"})
            data.update({'dealership_id': dealership_id, 'request_user_id': get_jwt_identity()})
            is_main_dealer = _get_result_as_dict(query_parser.get('dealers', '_get_main_dealer').format(dealership_id))
            if not is_main_dealer:
                return jsonify({'status': 'ERROR', 'message': 'No main applicant found.'})
            data.update({'mobile': is_main_dealer[0].get('mobile')})
            status, msg, available_limit = _credit_reload_amount_check(dealership_id, credit_reload_amount)
            if status:
                return jsonify({"status": "ERROR", "message": msg})
            if data.get("repayment_made") == "today" and not request.files:
                return jsonify({"status": "ERROR", "massage": "Please add the Payment Reference."})
            if request.files:
                status, files_url = s3_multi_file_upload(request.files, dealership_id)
                if not status:
                    return jsonify({'status': 'ERROR', 'message': 'Unable to attach payment proof.'})
                data.update({'payment_proof_attachment': files_url})
            affected, reload_request_id = mydb.run_query(mydb.INSERT,
                                                         mydb._gen_insert_query('t_credit_reload_history', data),
                                                         row_insert_id=True)
            _push_verified_banks_to_lms(bank_id=data.get('bank_id'))
            bank_details = _get_result_as_dict(query_parser.get('mdm_credit', '_get_bank_details').format(data.get('bank_id')))[0]
            bank_name = bank_details.get('bank_details')
            request_id = "PMR{}".format(datetime.datetime.now().date().strftime("%Y%m%d") + str(reload_request_id))
            _push_to_whatsapp(to=data.get('mobile'), type='template', message_content={"template": {
                "body": [{"type": "text", "text": "*{}*".format(data.get('amount'))},
                         {"type": "text", "text": '*' + bank_name + '*'},
                         {"type": "text", "text": '*' + request_id + '*'}], "langCode": "en",
                "templateId": 'reload_request'}})
            return jsonify(status='SUCCESS', message='Credit reload request submitted successfully. {}'.format(msg))
        elif id:
            crr_id = id[11:]
            if _is_vivriti_loan_product(crr_id):
                if data.get('reload_status') == 'Disbursed':
                    return jsonify({'status':"ERROR", 'message':"Couldn't disburse Vivriti product"})
                lms_response = _lms_data_handler(section = '', option = 'crr_decline_validation',data = {'crr_id': int(crr_id)}, use_mifin=False)
                if not lms_response:
                    raise Exception("Couldn't get valid respones from LMS to decline CRR")
                if not lms_response[0].get('can_decline'):
                    return jsonify({'status': 'ERROR', 'message': lms_response[0].get('user_msg')})
            if data.get('remarks'):
                affected, remark_id = mydb.run_query(mydb.INSERT, mydb._gen_insert_query('m_remarks', {
                    'remarks': "{0}".format(data.pop('remarks'))}), row_insert_id=True)
                data.update({'remarks_id': remark_id})
            result = _execute_query(mydb.UPDATE, mydb._gen_update_query('t_credit_reload_history',
                                                                        mydb._get_columns('t_credit_reload_history'),
                                                                        data)
                                    + " WHERE request_id = {}".format(crr_id))
            if data.get('reload_status'):
                request_history = _get_result_as_dict(query_parser.get('mdm_credit', '_get_credit_reload_history_by_id')
                                                      .format(crr_id))
                """This function used to push whatsapp notification with UTR."""
                if request_history[0].get('reload_status') == 'Disbursed':
                    data.update({'amount': request_history[0].get('amount'),
                                 'request_id': request_history[0].get('amount'),
                                 'urt': data.get('utr'),
                                 'type_of_account': request_history[0].get('type_of_account')})
                    transporters_whatsapp_notification('credit_request', data, [request_history[0].get('mobile')])
                else:
                    _push_to_whatsapp(to=request_history[0].get('mobile'), type='template', message_content={
                        "template": {"body": [{"type": "text", "text": request_history[0].get('amount')},
                                              {"type": "text", "text": request_history[0].get('request_id')},
                                              {"type": "text", "text": request_history[0].get('type_of_account')}],
                                     "langCode": "en", "templateId": "reload_response1"}})
            return result
    elif request.method == 'GET':
        args = dict(request.args)
        args.update({'dealership_id':args.get('dealership_id',dealership_id)})
        if args.get('processed') == '1' and not args.get('dealership_id'):
            return jsonify({'status':'ERROR', 'message':"Couldn't generate processed report without dealership_id"})
        sub_query = _gen_credit_reload_sub_query_based_on_filter(**args)
        if args.get('processed') == '1':
            sub_query += f" ORDER BY request_id DESC LIMIT {int(args.get('offset',0)) * 25},25"
        request_ids = _get_result_as_dict(sub_query)
        if not request_ids:
            return jsonify({'status':'SUCCESS','data':[],'stats':{'count':0,'amount':0}})
        request_ids = [str(i.get('request_id')) for i in request_ids]
        _credit_reload = _get_result_as_dict(query_parser.get('mdm_credit','_get_all_credit_reload_history').format('('+",".join(request_ids)+')'))
        _stats = _get_result_as_dict(sub_query.split('ORDER BY')[0].replace('request_id','count(1) as count, sum(amount) as amount'))
        return jsonify({'status':'SUCCESS','data':_credit_reload,'stats':_stats[0]})


@app.route('/api/credit/reload/typeofaccount', methods=['GET'])
@app.route('/api/credit/reload/account/type', methods=['GET'])
@jwt_required
def get_type_of_account():
    return _get_result(query_parser.get('mdm_credit', '_get_type_of_account'))


@app.route('/api/bot/delivery/report', methods=['POST'])
def _whatsapp_msg_report():
    data = request.get_json()
    _query = mydb._gen_insert_query('whatsapp_report', data)
    mydb.run_query(mydb.INSERT, _query)
    return jsonify(["success"])


def fuel_credit_due(_request_id, mobile):
    _id = mydb.run_query(mydb.SELECT, query_parser.get('dealers', '_get_dealership_id').format(mobile))
    if not _id:
        insert_option(_request_id, mobile, 0)
        return "No dealership found with this mobile number"
    _data = _get_loan_due_report(_id[0].get('dealership_id')).get_json()
    _dues = ""
    _over_dues = ""
    if _data.get("status") == "SUCCESS":
        if _data.get('data').get('due'):
            _dues = "*List of Due(s):*\n "
            for due in _data.get('data').get('due'):
                _dues = _dues + "Disbursement date : {0}\n " \
                                "Disbursement amount : {1}\n " \
                                "Due date : {2}\n " \
                                "*Principal due : {3}*\n " \
                                "*Interest due : {4}*\n " \
                                "*Total due : {5}*\n\n " \
                    .format(due.get("disb_date"),
                            due.get("disb_amt"),
                            due.get("duedate"),
                            due.get("prin_due"),
                            due.get("int_due"),
                            due.get("tot_due"))
        else:
            _dues = "No dues found.\n "

        if _data.get('data').get('overdue'):
            _over_dues = "*List of Overdue(s):*\n "
            for overdue in _data.get('data').get('overdue'):
                _over_dues = _over_dues + "Disbursement date : {0}\n " \
                                          "Disbursement amount : {1}\n " \
                                          "Due date : {2}\n " \
                                          "*Principal Overdue : {3}*\n " \
                                          "*Interest Overdue : {4}*\n " \
                                          "*Penal Overdue : {5}*\n " \
                                          "*Total Due : {6}* \n " \
                                          "*Days past Due (DPD): {7}*\n\n " \
                    .format(
                    overdue.get("disb_date"),
                    overdue.get("disb_amt"),
                    overdue.get("duedate"),
                    overdue.get("prin_overdue"),
                    overdue.get("int_overdue"),
                    overdue.get("penal_overdue"),
                    overdue.get("tot_due"),
                    overdue.get("dpd"))
        else:
            _over_dues = "No overdue found.\n "
        insert_option(_request_id, mobile, 0)
        return _dues + "\n" + _over_dues + "\n"


def credit_reload(_id, mobile):
    user_id = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_user_id').format(mobile))
    if not user_id:
        insert_option(_id, mobile, '0')
        return "Your mobile number is not registered with us."+_support_message
    user_id = user_id[0].get('id')
    data = mydb.run_query(mydb.SELECT, query_parser.get('credit', '_get_dealer_info').format(mobile))
    if data:
        data[0].pop('id')
        if not _dealership_loan_exists(data[0].get('dealership_id'), status="disbursed"):
            return "Sorry, no loan has been found for this account."+_support_message
        if not _get_result_as_dict(query_parser.get('credit','_get_verified_bank_by_dealership_id').format(data[0].get('dealership_id'))):
            return "Either no bank information is associated to us, or the information that is attached not " \
                   "verified. Use this link: https://mdm.petromoney.in/#/dealership/{}?t=4 to add and validate " \
                   "your bank information.".format(data[0].get('dealership_id'))
        data[0].update({'request_source': 'whatsapp', 'request_user_id': user_id, 'last_modified_by': user_id})
        mydb.run_query(mydb.DELETE,
                       query_parser.get('credit', '_remove_empty_credits').format(data[0].get('dealership_id')))
        credit_reload_result = mydb.run_query(mydb.INSERT, mydb._gen_insert_query('t_credit_reload_history', data[0]))
        insert_option(_id, mobile, 2)
        return get_response_from_table(2)


def is_number_valid(_id, mobile, amount, pre_id):
    amount = amount.replace(',', '').replace('.', ' ').replace('₹', '')
    amount = amount.split(' ')[0]
    if amount.isnumeric() and 50000 <= int(amount) <= 3000000:
        _get_dealer_info = query_parser.get('credit', '_get_dealer_info').format(mobile)
        data = mydb.run_query(mydb.SELECT, _get_dealer_info)
        if data:
            status, msg, available_limit = _credit_reload_amount_check(data[0].get('dealership_id'), int(amount))
            if status:
                insert_option(_id, mobile, '0')
                mydb.run_query(mydb.UPDATE, mydb._gen_update_query('t_credit_reload_history', ['reload_status'],
                                    {'reload_status': 'Declined'}) + f" WHERE mobile = '{mobile}' AND reload_status = 'In Progress' AND amount is NULL")
                return msg
            if msg:
                _push_to_whatsapp(to=mobile, type='text', id=_id, message_content={
                    "text": {"content": msg}})
            mydb.run_query(mydb.UPDATE, mydb._gen_update_query('t_credit_reload_history', ['amount'],
                                                               {'amount': amount}) + " WHERE mobile = '{}' AND reload_status = 'In Progress' AND amount is NULL".format(mobile))
            associated_bank_details = mydb.run_query(mydb.SELECT, query_parser.get('credit', '_get_verified_bank_by_dealership_id_with_serial_number').format(data[0].get('dealership_id')))
            return get_response_from_table(pre_id, _id, mobile).format(associated_bank_details[0].get('bank_details'))
    return "Invalid. Enter your amount between *50000* to *3000000* only."



@app.route('/api/credit/reload/<int:dealership_id>/limit')
@jwt_required
def get_credit_reload_available_limit(dealership_id = None):
    # Fetch the availabe amount limit for the given dealershipID to raise credit reload request.
    flag, msg, available_limit = _credit_reload_amount_check(dealership_id)
    return jsonify(status = 'SUCCESS', data = [{'available_limit': available_limit}])


def _credit_reload_amount_check(dealership_id=None, request_amount=0):
    _loan_id = _is_vivriti_loan_product(dealership_id= dealership_id)
    if _loan_id:
        _is_eligible = _lms_data_handler(section = '', option = 'fee_collection_and_limit_check',data = {'customer_application_id':_loan_id[0].get('id'), 'loan_amount': request_amount}, use_mifin=False)[0]
        if _is_eligible.get('is_eligible'):
            return False, 'Renewal fee will be deducted for this reload request.' if _is_eligible.get('fee_collection') else '', _is_eligible.get('eligible_amount')
        return True, f"Requested amount exceeds the total amount approved. Eligible limit is {_is_eligible.get('eligible_amount')} rupees only.", _is_eligible.get('eligible_amount')
    else:
        existing_amount = _get_result_as_dict(query_parser.get('credit', '_get_existing_amount').format(dealership_id))
        amount_approved = _get_result_as_dict(query_parser.get('credit', '_get_amount_approved').format(dealership_id))
        requested_amount_sum = existing_amount[0].get('requested_amount_sum')
        if amount_approved:
            amount_approved = amount_approved[0].get('amount_approved')
        else:
            amount_approved = 0
        available_limit = amount_approved - requested_amount_sum
        if (int(request_amount) + requested_amount_sum) > amount_approved:
            msg = f"Requested amount exceeds the total amount approved. Eligible limit is {available_limit} rupees only."
            return True, msg, available_limit
        return False, '', available_limit





def _update_type_of_account(_id, mobile, response, pre_id):
    _dealership_id = _get_result_as_dict(query_parser.get('credit', '_get_dealer_info').format(mobile))
    if response.isnumeric():
        _is_bank_details_exists = _get_result_as_dict(query_parser.get('credit','_verify_bank_details').format(_dealership_id[0].get('dealership_id'),response))
        if _is_bank_details_exists:
            _push_verified_banks_to_lms(account_no=_is_bank_details_exists[0].get('account_no'))
            mydb.run_query(mydb.UPDATE, mydb._gen_update_query('t_credit_reload_history', ['bank_id'],
                                                               _is_bank_details_exists[0]) + " WHERE mobile = '{}' AND reload_status = 'In Progress' AND bank_id is NULL".format(mobile))
            details = mydb.run_query(mydb.SELECT, query_parser.get('credit', '_get_amount').format(mobile))[0]
            return get_response_from_table(pre_id, _id, mobile).format(details.get('amount'),
                                                                       details.get('bank_details'))
    associated_bank_details = mydb.run_query(mydb.SELECT, query_parser.get('credit',
                                                                           '_get_verified_bank_by_dealership_id_with_serial_number').format(_dealership_id[0].get('dealership_id')))
    return "*Invalid Account type*. \n Kindly, choose the account category to deposit the credit amount.\n {}".format(associated_bank_details[0].get('bank_details'))


def _confirm_reload_request(_id, mobile, response, pre_id):
    details = mydb.run_query(mydb.SELECT, query_parser.get('credit', '_get_credit_reload_history_by_mobile')
                             .format(mobile))[0]
    num_regex='^[1-2]$'
    if re.search(num_regex,response):
        if int(response) == 1:
            return get_response_from_table(pre_id, _id, mobile, condition="pass").format(details.get('amount'),
                                                                                         details.get('request_id'))
        elif int(response) == 2:
            data = {'reload_status': 'Cancelled'}
            mydb.run_query(mydb.UPDATE, mydb._gen_update_query('t_credit_reload_history', list(data),
                                                               data) + " WHERE request_id = '{}'".format(details.get('req_id')))
            return get_response_from_table(pre_id, _id, mobile, condition="fail")
    return "Invalid Response. are you sure to raise the credit reload request for *₹{}* into your *{}* account? \n " \
           "1.Yes \n 2.No".format(details.get('amount'), details.get('type_of_account'))


def insert_option(_id, mobile, message):
    data = {'id': _id, 'from_ph': os.getenv('BOT_NUMBER'), 'to_ph': '91' + str(mobile), 'message': message}
    whatsapp_conversation_log_result = mydb.run_query(mydb.INSERT,
                                                      mydb._gen_insert_query('whatsapp_conversation', data))


def get_response_from_table(response_id, _id=None, mobile=None, action=False, condition=None):
    _query = query_parser.get('whatsapp', '_get_q_a_response')
    _get_response_and_action = mydb.run_query(mydb.SELECT, _query.format(response_id))
    if _get_response_and_action:
        _action = json.loads(_get_response_and_action[0].get('action'))
        _response = str(_get_response_and_action[0].get('response'))
    if action:
        return _action
    if all([_id, mobile]):
        if condition:
            response_text = mydb.run_query(mydb.SELECT, _query.format(_action.get(condition)))
            insert_option(_id, mobile, '0')
        else:
            response_text = mydb.run_query(mydb.SELECT, _query.format(_action.get('id')))
            insert_option(_id, mobile, _action.get('id'))
        return response_text[0].get('response')
    return _response


def statement_of_account(_id, mobile):
    insert_option(_id, mobile, 8)
    return get_response_from_table(8)


def get_financial_year(_id, option, mobile):
    current_date = datetime.datetime.now()
    current_fy_year = current_date.year if current_date.month >= 4 else current_date.year - 1
    if str(option) == '1':
        return '1-4-{}'.format(current_fy_year), '{}-{}-{}'.format(current_date.day, current_date.month,
                                                                   current_date.year)
    if str(option) == '2':
        return '1-4-{}'.format(current_fy_year - 1), '31-3-{}'.format(current_fy_year)
    if str(option) == '3':
        get_inception_date_from_mobile = _get_result_as_dict(
            query_parser.get('dealership', '_get_inception_date_from_mobile').format(mobile))
        if get_inception_date_from_mobile and get_inception_date_from_mobile[0].get('inception_date'):
            return get_inception_date_from_mobile[0].get('inception_date'), '{}-{}-{}'.format(current_date.day,
                                                                                              current_date.month,
                                                                                              current_date.year)
        _push_to_whatsapp(to=mobile, id=_id, type='text', message_content={'text': {
            'content': "Couldn't fetch inception date."+_support_message
        }})
        insert_option(_id, mobile, '0')
        return abort(jsonify(status="ERROR", message="Couldn't fetch"))


def soa_gen_report(_id, mobile, message, pre_id):
    if str(message) in ['1', '2', '3']:
        from_date, to_date = get_financial_year(_id, message, mobile)
        dealership_id = _get_result_as_dict(query_parser.get('credit', '_get_dealer_info').format(mobile))[0].get(
            'dealership_id')
        soa_report = _get_soa(dealership_id, from_date, to_date).get_json()
        if soa_report.get('status').upper() == 'SUCCESS':
            insert_option(_id, mobile, '0')
            _push_to_whatsapp(to=mobile, id=_id, type='media', message_content={'media': {
                "contentType": "application/pdf",
                "content": "",
                "caption": "Statement of Account",
                "mediaUrl": soa_report.get('file')
            }})
            return "SOA report for the duration : {} to {}".format(from_date, to_date)
        insert_option(_id, mobile, '0')
        return soa_report.get('message')
    return "Invalid option. Kindly choose a number between 1 to 3."


def request_callback(_id, mobile):
    data = {}
    _get_users_region_mapped = _get_result_as_dict(query_parser.get('users', '_get_users_region_mapped_RM_FO').format(mobile))
    _get_dealership_with_mobile = _get_result_as_dict(query_parser.get('users', '_get_dealership_with_mobile').format(mobile))
    """ this condition is used for check the users mapped regions details"""
    if not _get_users_region_mapped:
        return "user not mapped with any region"
    data.update({'dealership_id': _get_dealership_with_mobile[0].get('id'),
                 'name': _get_dealership_with_mobile[0].get('name'),
                 'mobile': mobile
                 })
    for user_data in _get_users_region_mapped:
        data.update({'first_name':user_data.get('first_name')})
        transporters_whatsapp_notification("callback", data, [user_data.get('mobile')])
    if _callback_request_exists(mobile):
        mydb.run_query(mydb.UPDATE, query_parser.get('whatsapp', '_update_callback_count').format(mobile))
        insert_option(_id, mobile, '0')
        return "Your callback request is received. You will receive a call shortly."
    user_id = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_user_id').format(mobile))
    query = mydb._gen_insert_query('t_callback_request', {"mobile": mobile, "last_modified_by": user_id[0].get("id")})
    mydb.run_query(mydb.INSERT, query)
    insert_option(_id, mobile, '0')
    return "Your callback request is registered. You will receive a call shortly."


# This API user to get all call logs for particular dealership_id
@app.route('/api/voicecall/logs/<int:dealership_id>', methods=['GET'])
# this API is not used for now, This is for future enhancement
@app.route('/api/voicecall/logs/<int:dealership_id>/<int:applicant_id>', methods=['GET'])
@jwt_required
def _voice_call(dealership_id=None, applicant_id=None):
    applicant_type = [{'dealer': 'm_dealers'}, {
        'coapplicant': 't_dealers_coapplicants'}, {'guarantor': 't_dealership_guarantors'}]
    _data = []

    """ this condition is not used for now, This is for future enhancement """
    if dealership_id and applicant_id:
        data = request.get_json()
        for i in applicant_type:
            for key, value in i.items():
                if key == data.get('type'):
                    logs = voice_call_logs(
                        dealership_id, key, value, applicant_id)
                    if logs:
                        _data = _data + logs
        if not _data:
            return jsonify({'status': 'ERROR', 'message': 'No logs Found!'})
        return jsonify({'data': _data})

    # Now This condition used
    elif dealership_id:
        for i in applicant_type:
            for key, value in i.items():
                # this function used to get the call log
                logs = voice_call_logs(dealership_id, key, value)
                if logs:
                    _data = _data + logs
        if not _data:
            return jsonify({'status': 'ERROR', 'message': 'No logs Found!'})
        return jsonify({'status': 'SUCCESS', 'data': _data})


def voice_call_logs(dealership_id=None, key=None, value=None, applicant_id=None):
    _data = []
    # in the future, this will be separated into a new function
    # this is used to get the user mapped regions
    region_in_list_of_dict = _get_result_as_dict(
        query_parser.get('users', '_get_user_region_id').format(get_jwt_identity()))
    mapped_regions = region_in_list_of_dict[0].get('region_id')
    if not mapped_regions:
        abort(jsonify({'status': 'ERROR', 'message': 'No region was mapped'}))
    # get mapped regions as in string format
    regions = tuple(mapped_regions.split(','))

    # this query used to get the call logs from 't_voice_call' Table
    _query = query_parser.get('voice_call', '_get_voice_logs')
    # this condition is not used for now, This is for future enhancement
    if applicant_id:
        applicant_id_query = ' and applicant_id = {0}'.format(applicant_id)
        _query = _query + applicant_id_query
    applicant_details = _get_result_as_dict(_query.format(
        dealership_id, key, (",".join(map(str, regions)))))
    # this fun is converted ['1','2'] to ('1','2')
    if applicant_details:
        for applicant_data in applicant_details:
            # this query used to get the applicant, name information
            name = _get_result_as_dict(query_parser.get('voice_call', '_get_voice_call_applicant_info').format(
                value, applicant_data.get('applicant_id')))
            if not name:
                abort(jsonify({'status': 'ERROR', 'message': 'No applicant found in this applicant Id - {}'.format(
                    applicant_data.get('applicant_id'))}))
            applicant_data.update(name[0])
            # this query used to get the user name, role information
            _get_user_info_by_mobile = _get_result_as_dict(query_parser.get(
                'users', '_get_user_info').format(applicant_data.get('from_mobile')))[0]
            applicant_data.update(
                {'first_name': _get_user_info_by_mobile.get('first_name'), 'last_name': _get_user_info_by_mobile.get(
                    'last_name'), 'role': _get_user_info_by_mobile.get('role_name')})
            _data.append(applicant_data)
    return _data


""" This API is used for making a voice call for the particular Applicant like dealer, co-applicant, guarantor """


@app.route('/api/dealership/<int:dealership_id>/applicant/voicecall', methods=['POST'])
@jwt_required
def _voice_call_integration(dealership_id=None):
    data = request.get_json()
    header = request.headers
    if header.get('isMobile'):
        _application_type = "Mobile (App)"
    else:
        _application_type = "MDM or Portal"
    applicant_type = data.pop('type')
    """  In the list of dict, KEY : applicant type and VALUE : applicant table """
    applicant_types = [{'dealer': 'm_dealers'}, {
        'coapplicant': 't_dealers_coapplicants'}, {'guarantor': 't_dealership_guarantors'}]
    if dealership_id:
        for applicant in applicant_types:
            for key, value in applicant.items():
                if key == applicant_type:
                    """ Is used to get the applicant id by using 'To mobile' and 'dealership_id'  """
                    _get_applicant_id = _get_result_as_dict(query_parser.get(
                        'general', '_get_voice_call_applicant_info_by_mobile').format(value, (data.get('To')),
                                                                                      dealership_id))
                    if not _get_applicant_id:
                        return jsonify({'status': 'ERROR',
                                        'message': 'No applicant Found in this mobile number - {}'.format(
                                            data.get('To'))})
    """  is used to get the login user mobile by using 'To mobile' and 'dealership_id' """
    _user_data = mydb.run_query(mydb.SELECT, query_parser.get(
        'users', '_get_user_details_by_id').format(get_jwt_identity()))
    if not _user_data:
        return jsonify(
            {'status': 'ERROR', 'message': 'No applicant Found in this mobile number - {}'.format(get_jwt_identity())})
    """ These data are  use for Exotel voice call input payload """
    data.update({"From": _user_data[0].get('mobile'), "CallerId": os.getenv(
        'CALLERID'), "StatusCallbackEvents[0]": 'terminal', 'StatusCallbackContentType': 'application/json'})
    """ this voice call data contains 3rd party API token, URL, etc..."""
    voicecall_data = {'url_path': os.getenv('voicecall_url_path'), 'api_key': os.getenv('voicecall_api_key'),
                      'token': os.getenv('voicecall_token'), 'voicecall_url_prefix': os.getenv('voicecall_url_prefix'),
                      'voicecall_url_suffix': os.getenv(
                          'voicecall_url_suffix'), 'headers': os.getenv('voicecall_headers'),
                      'sid': os.getenv('voicecall_sid'), 'uat_url': os.getenv('voicecall_UAT_url'),
                      'prod_url': os.getenv('voicecall_prod_url')}
    """ this _voice_call function is written in external.py. the 'bridge' used to access the '_voice_call' function. """
    message = bridge._voice_call(
        data, ENVIRONMENT, voicecall_data)
    _msg = message.json()
    """ 
    3rd party API return the result as 'Call' key-value ex: {'call' : {result_key : result_value}}. 
    so, Taken  'Call' key value only. 
    """
    msg = _msg.get('Call')
    if msg:
        """ These values are pop from msg and key value change from the Table field and stored into '_data' """
        _data = {}
        _data.update(
            {"dealership_id": dealership_id, "applicant_id": _get_applicant_id[0].get('id'), "sid": msg.pop("Sid"),
             "from_mobile": msg.pop(
                 "From"), "to_mobile": msg.pop("To"), "status": msg.pop("Status"), "details": msg,
             "applicant_type": applicant_type, "application_type": _application_type,
             "module": data.get('module')})
        col_list = mydb._get_columns('t_voice_call')
        query = mydb._gen_insert_query_exclude_cols("t_voice_call", col_list,
                                                    _data)
        mydb.run_query(mydb.INSERT, query)
        return jsonify({'status': 'SUCCESS', 'message': 'Call Connected Successfully'})
    return jsonify({'status': 'ERROR', 'message': 'Call Could not be Connect'})


""" this API act as an 'outbound-API for 'voice_call' 3rd party API. Outbound- API means, '/api/dealership/<int:dealership_id>/applicant/voicecall' api only give the final response in another POST API."""


@app.route('/api/voicecall', methods=['POST'])
def _voice_call_url_sender():
    """ '/api/dealership/<int:dealership_id>/applicant/voicecall' final response stored in data variable. """
    data = request.get_json()
    """ 3rd party API final response stored into Table separate Fields, So changed the key value as dict format and stored in to '_data' variable """
    _data = {}
    _data.update({'start_time': data.pop('StartTime'), 'end_time': data.pop('EndTime'), 'recording_url': data.pop(
        'RecordingUrl'), 'status': data.pop('Status'), 'recording_details': data,
                  'duration': data.pop('ConversationDuration')})
    col_list = mydb._get_columns('t_voice_call')
    query = mydb._gen_update_query("t_voice_call", col_list,
                                   _data)
    _query = query + " WHERE sid = '{}'".format(data.get('CallSid'))
    mydb.run_query(mydb.INSERT, _query)
    return jsonify({'status': 'SUCCESS', 'message': 'Response stored successfully'})


"""" This API is used to inactive the voice call logs """


@app.route('/api/voicecall/log/<int:id>', methods=['DELETE'])
@jwt_required
def _deactivate_log(id=None):
    if id:
        if _get_user_role(get_jwt_identity()) == 1:
            data = {}
            """ convered is_active = 1 to is_active = 0 """
            data.update({'is_active': 0})
            query = mydb._gen_update_query("t_voice_call", mydb._get_columns('t_voice_call'),
                                           data) + " WHERE id = '{}'".format(id)
            affected = mydb.run_query(mydb.UPDATE, query)
            if not affected:
                return jsonify({"status": "ERROR",
                                "message": "Log has not been deleted properly."+_support_message})
            return jsonify({"status": "SUCCESS", "message": "Log Deleted successfully"})
        return jsonify({"status": "ERROR", "message": "Unauthorized Access, "+_support_message})


@app.route('/api/customer/callback', methods=['GET', 'POST'])
@app.route('/api/customer/callback/<int:request_id>', methods=['POST'])
@jwt_required
def customer_callback(request_id=None):
    if request.method == 'GET':
        region_in_list_of_dict = _get_result_as_dict(
            query_parser.get('users', '_get_user_region_id').format(get_jwt_identity()))
        mapped_regions = region_in_list_of_dict[0].get('region_id')
        if not mapped_regions:
            return jsonify({'status': 'ERROR', 'message': 'No region was mapped'})
        regions = tuple(mapped_regions.split(','))
        _query = query_parser.get('whatsapp', '_get_callback_requests').format(request.args.get('is_processed', 0),
                                                                               (",".join(map(str, regions))))
        return _get_result(_query)
    if request.method == 'POST':
        data = request.get_json()
        data.update({'last_modified_by': get_jwt_identity()})
        if request_id:
            return _execute_query(mydb.UPDATE,
                                  mydb._gen_update_query('t_callback_request', mydb._get_columns('t_callback_request'),
                                                         data) + "WHERE request_id = '{}'".format(request_id))
        else:
            return _execute_query(mydb.INSERT, mydb._gen_insert_query('t_callback_request', data))


@app.route('/api/business/projection', methods=['GET'])
def business_projection():
    data = {}
    data.update({"current": _get_result_as_dict(query_parser.get('projection', '_get_business_projection'))[0],
                 "projection":
                     _get_result_as_dict(query_parser.get('projection', '_get_business_projection_opportunity'))[0]})
    return jsonify({"data": [data], "status": "SUCCESS"})


@app.route('/api/projection', methods=['GET'])
@jwt_required
def projection():
    return jsonify(
        {"status": "SUCCESS", "data": lms('_get_projection')})


def opportunities(omc_opportunities, conversion_ratio, ticket, omc_list):
    for i in range(len(omc_opportunities)):
        sum = 0
        for omc in omc_list:
            omc_value = omc_opportunities[i].get(omc)
            if omc_value:
                sum += int(omc_value)
        converted_dealers_count = round(sum * conversion_ratio)
        average_ticket_counts = round((converted_dealers_count * ticket) / 10000000)
        omc_opportunities[i].update({"opportunities": sum, "converted_dealers_count": converted_dealers_count,
                                     "average_ticket_count": average_ticket_counts})
    return omc_opportunities


def opportunities_total(output, omc_list):
    total_keys = omc_list + ["conversion_ratio", "average_ticket_count", "opportunities", "converted_dealers_count"]
    total = {}
    for key in total_keys:
        key_total = 0
        for output_value in output:
            value = output_value.get(key)
            if value:
                key_total += value
                key_name = "total_" + key
                total.update({key_name: key_total})
    return total


def groupby_list_dict(result):
    for result_value in result:
        if not result_value.get("name"):
            result_value.update({"name": "Others"})
    output = []
    result = sorted(result, key=lambda k: k['name'])
    for key, value in groupby(result, lambda k: k['name']):
        temp = {}
        count = 0
        for group_by_value in value:
            temp.update(group_by_value)
            omc_count = group_by_value.pop('omc_count')
            count += omc_count
            temp.update({group_by_value.pop('omc_name'): omc_count, "opportunities": count})
        temp.pop('omc_name')
        temp.pop('omc_count')
        output.append(temp)
    return output


def find_omc_opportunities(output, groupby_exist_result, omc_list):
    for exist_omc in groupby_exist_result:
        for opportunities_omc in output:
            for omc in omc_list:
                if opportunities_omc.get("name") == exist_omc.get("name") and opportunities_omc.get(
                        omc) and exist_omc.get(omc):
                    value = opportunities_omc.get(omc) - exist_omc.get(omc)
                    opportunities_omc.update({omc: value})
    return output


@app.route('/api/potential/opportunities', methods=['GET'])
@jwt_required
def potential_opportunities():
    if str(_get_user_role(get_jwt_identity())) in POTENTIAL_OPPORTUNITIES_ROLE_ACCESS_LIST:
        conversion_ratio = int(request.args.get("conversion_ratio")) / 100 if request.args.get(
            "conversion_ratio") else 0.3
        ticket = int(request.args.get("ticket_size")) * 100000 if request.args.get("ticket_size") else 1500000
        _view = request.args.get('view', 'state')
        result = mydb.run_query(mydb.SELECT,
                                query_parser.get('potential_opportunities', '_get_potential_opportunities').format(
                                    _view))
        exist_omc_result = mydb.run_query(mydb.SELECT,
                                          query_parser.get('potential_opportunities', '_get_existing_omc').format(
                                              _view))

        omc_list = mydb.run_query(mydb.SELECT, query_parser.get('potential_opportunities', '_get_omc'))
        if not omc_list:
            return jsonify({"status": "ERROR", "message": "Invalid Data"})
        omc_list = [d.get('omc') for d in omc_list]
        groupby_exist_result = groupby_list_dict(exist_omc_result)
        groupy_opportunities_result = groupby_list_dict(result)
        omc_opportunities = find_omc_opportunities(groupy_opportunities_result, groupby_exist_result, omc_list)
        result = opportunities(omc_opportunities, conversion_ratio, ticket, omc_list)
        total = opportunities_total(result, omc_list)
        return jsonify({"status": "SUCCESS", "data": {"result": result, "total": [total]}})
    return jsonify({"status": "ERROR", "message": "Unauthorized access."+_support_message})


@app.route('/api/app/dpd/report', methods=['GET'])
@jwt_required
def dpd_report():
    return jsonify(
        {"status": "SUCCESS", "data": lms('_get_dpd_report')})


def find_trail(_id, q_no, mobile_number):
    q_no_map = {
        "1": lambda _id, mobile: fuel_credit_due(_id, mobile_number),
        "2": lambda _id, mobile: credit_reload(_id, mobile_number),
        "3": lambda _id, mobile: statement_of_account(_id, mobile_number),
        "4": lambda _id, mobile: request_callback(_id, mobile_number),
    }
    if q_no in ['1', '2', '3', '4']:
        return q_no_map.get(str(q_no))(_id, mobile_number)
    return "Invalid response. Choose Number between 1 to 4"


@app.route('/api/whatsapp/send', methods=['POST'])
@jwt_required
def send_message():
    data = request.get_json()
    return _push_to_whatsapp(to=data.get('to'), type=data.get('type'), message_content=data.get('message_content'))


def _push_to_whatsapp(**data):
    if not data:
        data = request.get_json()
    request_details = _get_result_as_dict(query_parser.get('external', '_get_external_api_value').format('WHATSAPP'))[0]
    url = request_details.get('base_url_{}'.format(ENVIRONMENT.lower()))
    payload = {
        "messages": [
            {
                "sender": os.getenv('BOT_NUMBER'),
                "to": data.get('to'),
                "channel": "wa",
                "type": data.get('type')
            }
        ],
        "responseType": "json"
    }
    payload.get('messages')[0].update({'transaction_id': data.get('id') if data.get('id') else ''.join(
        random.choices(string.ascii_uppercase + string.digits, k=17))})
    payload.get('messages')[0].update(data.get('message_content'))
    whatsapp_response = req.post(url, json=payload,
                                 headers=json.loads(request_details.get('{}_header'.format(ENVIRONMENT.lower()))))
    if whatsapp_response:
        """response object converted into dictionary"""
        response = whatsapp_response.json()
        if response.get('success') == 'false':
            logger.info("Notification report -> {}".format(json.dumps(response)))
        return response
    else:
        logger.info("Unable to get whatsapp response")


@app.route('/api/bot', methods=['POST'])
def _whatsapp_bot(_trail=0, _pre=""):
    data = request.get_json().get("message")
    mobile = data.get('from')
    _id = data.get('id')
    if not _dealer_exists(mobile[2:]):
        return _push_to_whatsapp(to=mobile, type='text', id=_id, message_content={
            "text": {"content": "Dealer is not registered with Petromoney. "+_support_message}})
    if not data.get('text'):
        return _push_to_whatsapp(to=mobile, type='text', id=_id, message_content={
            "text": {"content": "Invalid input, please type 'Hi' to start a conversation"}})
    user_message = data.get('text').get('body')
    data.update({"from_ph": mobile, "to_ph": data.get('to'), "message": user_message})
    _cols = mydb._get_columns('whatsapp_conversation')
    _query = mydb._gen_insert_query_exclude_cols('whatsapp_conversation', _cols, data)
    mydb.run_query(mydb.INSERT, _query)
    if 'hi' in user_message.lower():
        data.update({"message": 1, 'to_ph': data.pop('from_ph'), 'from_ph': os.getenv('BOT_NUMBER')})
        _query = mydb._gen_insert_query_exclude_cols('whatsapp_conversation', _cols, data)
        mydb.run_query(mydb.INSERT, _query)
        message = "Hi, I am Petroman. How can I help you?\n" \
                  "1. Outstanding Fuel Credit\n" \
                  "2. Request Loan reload\n" \
                  "3. Statement of Accounts\n" \
                  "4. Request callback\n"
        return _push_to_whatsapp(to=mobile, type='text', id=_id, message_content={"text": {"content": message}})
    if user_message:
        _prev = mydb.run_query(mydb.SELECT, query_parser.get('whatsapp', '_get_previous_conversation').format(
            os.getenv('BOT_NUMBER'), mobile))
        if _prev:
            _prev = _prev[0]
            if _prev.get('message') == '1':
                return _push_to_whatsapp(to=mobile, type='text', id=_id, message_content={
                    "text": {"content": find_trail(_id, user_message, mobile[2:])}})
            elif _prev.get('message') == '0':
                return _push_to_whatsapp(to=mobile, type='text', id=_id,
                                         message_content={"text": {"content": "Say *Hi* to start conversation!"}})
            else:
                action = get_response_from_table(_prev.get('message'), action=True)
                message = "Invalid input."+_support_message
                if action:
                    message = globals().get(action.get('function'))(_id, mobile[2:], user_message, _prev.get('message'))
                return _push_to_whatsapp(to=mobile, type='text', id=_id, message_content={"text": {"content": message}})
        return _push_to_whatsapp(to=mobile, type='text', id=_id,
                                 message_content={"text": {"content": "Say *Hi* to start conversation!"}})
    else:
        return _push_to_whatsapp(to=mobile, type='text', id=_id, message_content={
            "text": {"content": "Invalid message input, type Hi to initiate the conversation."}})


@app.route('/api/v1/addoptinpost', methods=['POST'])
def whatsapp_add_optin(numbers=None):
    if not numbers:
        if not request.get_json().get('numbers'):
            return jsonify(
                {"status": "ERROR", "message": "Couldn't process your request."+_support_message})
        numbers = request.get_json().get('numbers')
    _exists_mobile_numbers = _get_result_as_dict(query_parser.get('whatsapp_notification', '_get_exists_opt_in_mobile'))
    _exists_mobile_numbers = list(map(itemgetter('mobile'), _exists_mobile_numbers))
    numbers = list(filter(lambda element: element not in _exists_mobile_numbers, map(int, numbers)))
    if not numbers:
        return jsonify({'status': 'SUCCESS', 'message': 'Already in Opt-in'})
    request_details = \
        _get_result_as_dict(query_parser.get('external', '_get_external_api_value').format('WHATSAPP_OPT-IN'))[0]
    url = request_details.get('base_url_{}'.format(ENVIRONMENT.lower()))
    payload = json.loads(request_details.get('{}_header'.format(ENVIRONMENT.lower())))
    payload.update({'msisdnList': numbers})
    response = req.post(url, json=payload).json()
    mydb._bulk_insert(mydb._gen_bulk_insert_query('t_whatsapp_optin', ['mobile']), numbers)
    return jsonify(status="SUCCESS", message="Successfully added.")


# Login route
# Use the set_access_cookie() and set_refresh_cookie() on a response. By default, the CRSF cookies will be called csrf_access_token and
# csrf_refresh_token, and in protected endpoints we will look for the CSRF token in the 'X-CSRF-TOKEN' header. You can modify all of these
# with various app.config options. Check the options page for details. JWT_COOKIE_CSRF_PROTECT set to True, set_access_cookies() and
# set_refresh_cookies() will now also set the non-httponly CSRF cookies as well
@app.route('/api/login/otp', methods=['POST'])
def login():
    mobile = request.json.get('mobile', None)
    if mobile:
        _get_user = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_user_info').format(mobile))
        if len(_get_user):
            if _get_user[0].get('user_status') == 0:
                return jsonify({"status": "ERROR", "message": "User do not exist"})
            send_otp(_get_user[0].get('mobile'), OTP_TEMPLATE, 2)
            return jsonify(
                {'status': 'SUCCESS', 'mobile': _get_user[0].get('mobile'), 'role_id': _get_user[0].get('role_id')})
        else:
            return jsonify({'status': 'ERROR', 'message': 'User does not exist.'})
    else:
        return jsonify({'status': 'ERROR', 'message': 'Missing mobile number.'})


@app.route('/api/password/reset', methods=['POST'])
def password_reset():
    mobile = request.json.get('mobile')
    otp = request.json.get('otp')
    _status, _msg = verify_otp(mobile, otp)
    if _status:
        password = request.json.get('password')
        if password:
            encode_password = _hash_password(password)
            cols = mydb._get_columns("m_users")
            query = mydb._gen_update_query("m_users", cols, ({'password': encode_password}))
            return _execute_query(mydb.UPDATE, query + " WHERE mobile={0}".format(mobile))
        return jsonify({'status': 'ERROR', 'message': 'Please enter Password'})
    else:
        return jsonify({'status': 'ERROR', 'message': _msg})


@app.route('/api/user/consent', methods=['POST'])
def _is_consent(user_id=None):
    """This APi used to accept terms and conditions"""
    data = request.get_json()
    is_consent = data.get('is_consent')
    if not is_consent:
        return jsonify({'status': 'ERROR', 'message': "Please accept the Terms and Conditions"})
    _execute_query(mydb.UPDATE, query_parser.get('users', '_update_is_consent').format(is_consent, data.get('user_id')))
    return jsonify({'status': 'SUCCESS', 'message': 'Terms and conditions accepted'})


@app.route('/api/login/user', methods=['POST'])
def login_user_otp():
    data = request.get_json()
    mobile = data.get('mobile')
    if not validate._is_mobile(str(mobile)):
        return jsonify({'status': 'ERROR', 'message': 'Incorrect request'})
    _user_data = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_user_info').format(mobile))
    error_msg = ''
    if not _user_data:
        error_msg = "Unauthorized access, user do not exist"
        logger.debug(error_msg + " - {}".format(mobile))
    if _user_data and not _user_data[0].get('user_status'):
        error_msg = "User is inactive."+_support_message
    if error_msg:
        return jsonify({'status': 'ERROR', 'message': error_msg})
    user_id = _user_data[0].get('id')
    data.update({"user_id": user_id})
    header = request.headers
    if header.get('isMobile'):
        data.update({"application_type": "Mobile (App)", "details": {"deviceId": header.get('deviceId'),
                                                                     "appVersion": header.get('appVersion'),
                                                                     "osType": header.get('appVersion')}})
    else:
        data.update({"application_type": "MDM or Portal", "details": {"User-Agent": header.get('User-Agent')}})
    password = data.get('password')
    otp = data.get('otp')
    if otp:
        _status, _msg = verify_otp(mobile, otp)
        if _status:
            login_history(data)
            return _get_user_data(mobile, password)
        else:
            return jsonify({'status': 'ERROR', 'message': _msg})
    elif password:
        login_history(data)
        return _get_user_data(mobile, password)
    else:
        return jsonify({'status': 'ERROR', 'message': 'Login requires Password or OTP.'})


def login_history(data):
    login_history_cols = mydb._get_columns('user_login_history')
    query = mydb._gen_insert_query_exclude_cols('user_login_history', login_history_cols, data)
    affected_rows = mydb.run_query(mydb.INSERT, query)
    if not affected_rows:
        logger.info("Unable to update login history for user with mobile - {}".format(data.get('mobile')))


def _get_user_data(mobile, password):
    result = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_user_info').format(mobile))
    data = {}
    if len(result) != 0:
        result = result[0]

        if result.get('user_status') == 0:
            return jsonify({"status": "ERROR", "message": "Unauthorized Access, user do not exist."})
        if password:
            if not _verify_password(result.get('password'), password):
                return jsonify({'status': 'ERROR', 'message': 'Incorrect username or password'})
        data.update(
            {'id': result.get('id'), 'first_name': result.get('first_name'), 'last_name': result.get('last_name'),
             'mobile': result.get('mobile'),
             'email': result.get('email'), 'role_id': result.get('role_id'),
             'role_name': result.get('role_name'), 'role_desc': result.get('role_desc'),
             'is_consent': result.get('is_consent')})
        data.update({"regions_mapped": _get_user_regions(result.get('id'))})
        _get_regions = mydb.run_query(mydb.SELECT,
                                      query_parser.get('users', '_get_user_region_info').format(result.get('id')))
        if len(_get_regions):
            data.update(
                {'region_id': _get_regions[0].get('region_id'),
                 'region_name': _get_regions[0].get('region_name')})
        if data.get('role_id') == 13:
            response = mydb.run_query(mydb.SELECT, query_parser.get('dealers', '_get_dealership_id').format(mobile))
            if len(response):
                data.update({'dealership_id': response[0].get('dealership_id')})
            else:
                return jsonify(
                    {'status': 'ERROR', 'message': 'Unable to Login, no dealers found with this mobile number.'})
        if data.get('role_id') == 14:
            response = mydb.run_query(mydb.SELECT,
                                      query_parser.get('transporters', '_get_transporter_id').format(mobile))
            if len(response):
                data.update({'transporters': response})
        # Create the tokens we will be sending back to the user
        expires = datetime.timedelta(days=1)
        access_token = create_access_token(identity=data.get('id'), expires_delta=expires)
        refresh_token = create_refresh_token(identity=data.get('id'))
        data.update({'token': access_token, 'refresh_token': refresh_token})
        # Set the JWT cookies in the response
        return jsonify({'status': 'SUCCESS', 'message': 'Login success', 'data': data})
    else:
        return jsonify({'status': 'ERROR', 'message': 'User does not exists.'})


def _login_trail(data):
    _query = mydb._gen_insert_query('t_login_history', data)
    affected_rows = mydb.run_query(mydb.INSERT, _query)
    return True if affected_rows > 0 else False


@app.route('/api/users', methods=['GET'])
@jwt_required
def _get_all_users():
    current_user = get_jwt_identity()
    user_role = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_user_role').format(current_user))
    _allowed_roles = [1, 2, 4, 3, 6, 8, 9, 10, 11]
    if user_role[0].get('role_id') in _allowed_roles:
        query = query_parser.get('users', '_get_user_details')
        if str(request.args.get('is_review')) == '1':
            query += " WHERE role_id IN {} AND status=1 AND u.id<>{}".format((10, 11), current_user)
        elif str(request.args.get('is_approve')) == '1':
            query += " WHERE role_id IN {} AND status=1 AND u.id<>{}".format((11, 2, 4), current_user)
        return _get_result(query)
    return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_unauthorized')})


# Because the JWTs are stored in an httpOnly cookie now, we cannot log the user out by simply deleting the cookie
# in the frontend. We need the backend to send us a response to delete the cookies in order to logout.
# unset_jwt_cookies is a helper function to do just that.
@app.route('/api/logout', methods=['POST'])
def logout():
    return jsonify({'status': 'SUCCESS', 'logout': True})


@app.route('/api/login/check', methods=['POST'])
@jwt_refresh_token_required
def login_check():
    # Create the new access token
    current_user = get_jwt_identity()
    expires = datetime.timedelta(days=1)
    access_token = create_access_token(identity=current_user, expires_delta=expires)
    # Set the access JWT and CSRF double submit protection cookies in this response
    logger.debug('The JWT auth token has been refreshed.')
    return jsonify({'status': 'SUCCESS', 'data': access_token, 'refresh': True})


@app.route('/api/signup', methods=['POST'])
@jwt_required
def _signup_user():
    if not _get_user_role(get_jwt_identity()) == 1:
        return jsonify({"status": "ERROR", "message": "Unauthorized Access, "+_support_message})
    data = request.get_json()
    if data.get('role_id') == '13':
        return dealer_signup(data, skip_headers=True)
    elif data.get('role_id') == '14':
        return transporter_signup(data, skip_headers=True)
    else:
        return _signup(data)


@app.route('/api/user/<int:user_id>', methods=['POST'])
@jwt_required
def _update_user_details(user_id=None):
    if user_id:
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity()})
        _user_cols = mydb._get_columns('m_users')
    if "password" in data:
        data.update({'password': _hash_password(data.get('password'))})
    if data.get('role_id') == 13:
        _is_main_applicant_data = {}
        is_main_applicant_data = {key: data.get(key) for key in USER_MAINAPPLICANT_FIELDS if data.get(key)}
        _is_main_applicant_data.update(is_main_applicant_data)
        check_dealer_data = _get_result_as_dict(query_parser.get(
            'users', '_get_user_details_by_id').format(user_id))[0]
        _dealers_col_list = mydb._get_columns('m_dealers')
        _query = mydb._gen_update_query("m_dealers", _dealers_col_list, _is_main_applicant_data)
        _execute_query(mydb.UPDATE, _query + " WHERE mobile ='{0}' and first_name = '{1}' and last_name= '{2}'".format(
            check_dealer_data.get('mobile'), check_dealer_data.get('first_name'), check_dealer_data.get('last_name')))
    elif data.get('role_id') == 14:
        is_main_applicant_data = {key: data.get(key) for key in USER_MAINAPPLICANT_FIELDS if data.get(key)}
        check_dealer_data = _get_result_as_dict(query_parser.get(
            'users', '_get_user_details_by_id').format(user_id))[0]
        _dealers_col_list = mydb._get_columns('t_transports')
        _query = mydb._gen_update_query("t_transports", _dealers_col_list, is_main_applicant_data)
        _execute_query(mydb.UPDATE, _query + " WHERE mobile ='{0}'".format(
            check_dealer_data.get('mobile')))
    if _user_exists(user_id):
        _query = mydb._gen_update_query('m_users', _user_cols, data)
        return _execute_query(mydb.UPDATE, _query + " WHERE id={}".format(user_id))
    else:
        return jsonify(
            {"status": "ERROR",
             "message": "User not found."+_support_message})


@app.route('/api/user/<int:user_id>', methods=['DELETE'])
@jwt_required
def _disable_user(user_id=None):
    if user_id:
        mydb.run_query(mydb.UPDATE,
                       "UPDATE m_users SET status=0, last_modified_by={0} WHERE id={1}".format(get_jwt_identity(),
                                                                                               user_id))
        return jsonify({"status": "SUCCESS", "message": "The user has been disabled."})


@app.route('/api/user/account', methods=['DELETE'])
@jwt_required
def _delete_user_account():
    _affected_rows = mydb.run_query(mydb.INSERT,
                                    f"INSERT into deleted_users SELECT * FROM m_users where id={get_jwt_identity()};")
    if not _affected_rows:
        return jsonify({"status": "ERROR", "message": "The user account can not be deleted."})
    mydb.run_query(mydb.DELETE, f"DELETE from m_users where id={get_jwt_identity()};")
    return jsonify({"status": "SUCCESS", "message": "The user account is deleted."})


def _signup_otp_verify(data=None, skip_headers=False):
    header = request.headers
    if not skip_headers:
        if not all([data, data.get('mobile'), data.get('otp')]):
            abort(jsonify({"status": "ERROR", "message": "Could not verify OTP. Missing mobile or OTP details."}))
        if not header.get('ismobile'):
            abort(jsonify({"status": "ERROR", "message": "Invalid signup request source. "+_support_message}))
        else:
            _status, _msg = verify_otp(data.get('mobile'), data.pop('otp'))
            if not _status:
                abort(jsonify({"status": _status, "message": _msg}))


@app.route('/api/signup/dealer', methods=['POST'])
def dealer_signup(data=None, skip_headers=False):
    if not data:
        data = request.get_json()
    _signup_otp_verify(data, skip_headers)
    _signup_response = _signup(data)
    data.update(
        {'id': data.get('dealership_id'), 'name': data.get('dealership_name'), 'role_id': data.get('role_id', 13),
         'email': data.get('email', ''), 'password': data.get('password', 'Petromall@2020')})
    if _signup_response.get_json().get('status') == 'SUCCESS':
        dealership_cols = ["id", "name", "business_type", "pincode", "omc", "region", "state"]
        dealer_cols = ["dealership_id", "first_name", "last_name", "email", "mobile", "is_main_applicant",
                       "is_aadhar_linked", "is_whatsapp"]
        try:
            _insert_dealership = mydb._gen_upsert_query("m_dealership", dealership_cols, data)
            _execute_query(mydb.INSERT, _insert_dealership)
            data.update({"is_main_applicant": "1"})
            _insert_dealer = mydb._gen_upsert_query("m_dealers", dealer_cols, data)
            _execute_query(mydb.INSERT, _insert_dealer)
        except Exception as e:
            logger.error("Dealership/Dealer details can not be updated due to an error: {}".format(e))
    return _signup_response


@app.route('/api/signup/transporter', methods=['POST'])
def transporter_signup(data=None, skip_headers=False):
    if not data:
        data = request.get_json()
    _signup_otp_verify(data, skip_headers)
    data.update({'role_id': data.get('role_id', 14), 'email': data.get('email', ''),
                 'password': data.get('password', 'Petromall@2020')})
    return _signup(data)


def _signup(data):
    if (not data.get('first_name')) or (not data.get('email')) or (not data.get('mobile')):
        return jsonify({'status': 'ERROR', 'message': 'Missing user details (First name, Email or Mobile)'})
    _user_exists = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_user_info').format(data.get('mobile')))
    if _user_exists:
        return jsonify({'status': 'ERROR', 'message': 'User with this mobile number exists, log in to continue.'})
    data.update({'password': _hash_password(data.get('password', 'Petromall@2020'))})
    _user_cols = mydb._get_columns('m_users')
    _user_query = mydb._gen_insert_query_exclude_cols('m_users', _user_cols, data)
    affected_rows, pm_user_id = mydb.run_query(mydb.INSERT, _user_query, True)
    if not affected_rows:
        return jsonify({'status': 'ERROR', 'message': 'Failed to add new user account.'})
    if data.get('role_id') == 14:
        # data.update({'t_owner_id': pm_user_id})
        # _cols = mydb._get_columns('t_transport_owners')
        _cols = mydb._get_columns('t_transports')
        # _query = mydb._gen_insert_query_exclude_cols('t_transport_owners', _cols, data)
        _query = mydb._gen_insert_query_exclude_cols('t_transports', _cols, data)
        affected_rows = mydb.run_query(mydb.INSERT, _query)
        if not affected_rows:
            logger.debug('Failed to add new Transport owner account.')
    return jsonify(
        {'status': 'SUCCESS', 'message': 'Welcome to Petromoney. Please, login to access your user account.'})


# Protected route
@app.route('/api/user/roles', methods=['GET', 'POST'])
def user_roles():
    if request.method == 'POST':
        data = request.get_json()
        qry = "INSERT INTO m_roles(role_name, role_desc) values('{0}', '{1}')" \
              " ON DUPLICATE KEY UPDATE role_desc='{1}'" \
            .format(data.get('name'), data.get('desc'))
        affected_rows = mydb.run_query(mydb.INSERT, qry)
        if affected_rows:
            return jsonify({'status': 'SUCCESS'})
        else:
            return jsonify({'status': 'ERROR', 'message': 'Failed to add user role'})
    elif request.method == 'GET':
        result = mydb.run_query(mydb.SELECT, 'SELECT id, role_name, role_desc as name from m_roles')
        return jsonify({'status': 'SUCCESS', 'data': result})


@app.route('/api/vehicle/loan/options', methods=['GET', 'POST'])
@app.route('/api/vehicle/loan/options/<int:id>', methods=['DELETE'])
def transporter_loan_options(id=None):
    if request.method == 'POST':
        data = request.get_json()
        if id:
            qry = "INSERT INTO m_transporter_loan_options(credit_head, credit_desc, is_service) values('{0}', '{1}')" \
                  " ON DUPLICATE KEY UPDATE credit_desc='{1}'" \
                .format(data.get('credit_head'), data.get('credit_desc'), data.get('is_service', 0))
            return _is_rows_affected(qry)
    elif request.method == 'GET':
        result = mydb.run_query(mydb.SELECT,
                                'SELECT id, credit_head, credit_desc, is_service from m_transporter_loan_options')
        return jsonify({'status': 'SUCCESS', 'data': result})


@app.route('/api/support/list', methods=['GET'])
@jwt_required
def support_list():
    """This APi used to get support list details"""
    allowed_support = {
        "DEALER": "'FIELD_OFFICER', 'SALES_HEAD_STATE', 'SALES_HEAD_REGIONAL'",
        "TRANSPORTER": "'FIELD_OFFICER', 'SALES_HEAD_STATE', 'SALES_HEAD_REGIONAL'",
        "FIELD_OFFICER": "'SALES_HEAD_STATE', 'SALES_HEAD_REGIONAL'",
        "SALES_HEAD_REGIONAL": "'SALES_HEAD_STATE'",
        "SALES_HEAD_STATE": "'ADMIN'"
    }
    logged_in_user_id = get_jwt_identity()
    logged_in_user_role = mydb.run_query(mydb.SELECT,
                                         query_parser.get('users', '_get_user_role_name').format(
                                             logged_in_user_id))[0].get("role_name")
    if logged_in_user_role not in list(allowed_support):
        return jsonify(
            {'status': 'ERROR', 'message': 'Support personnel unassigned. '+_support_message})
    support_details = []
    if logged_in_user_role == "SALES_HEAD_STATE":
        support_details = mydb.run_query(mydb.SELECT,
                                         query_parser.get('users', '_get_admin_contact_details').format(
                                             int(os.getenv("ADMIN_SUPPORT_ID"))))
    else:
        support_details = mydb.run_query(mydb.SELECT,
                                         query_parser.get('general', '_get_support_list').format(
                                             user_id=logged_in_user_id,
                                             role_list=allowed_support.get(
                                                 logged_in_user_role)))
    if not support_details:
        return jsonify({"status": "ERROR", "message": "Support personnel unassigned. " + _support_message})
    return jsonify({'status': 'SUCCESS', 'data': support_details})


@app.route('/api/dealership', methods=['GET'])
@app.route('/api/dealership/<int:id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def dealership(id=None):
    if request.method == 'POST':
        data = format_date_in_data(encrypt_data(dict(request.form)),
                                   ['doi', 'agreement_executed_on', 'agreement_valid_till'])
        if request.files:
            _status_, result = _upload_kyc_docs(request.files, origin_id=id, type='dealers')
            if _status_:
                data.update(result)
            else:
                return jsonify({'status': 'ERROR', 'message': result})
        if id:
            col_list = mydb._get_columns("m_dealership")
            query = mydb._gen_update_query("m_dealership", col_list, data)
            return _is_rows_affected(query + " WHERE id = {}".format(id), True, 1, id)
    elif request.method == 'GET':
        if id and id > 0:
            return _get_result(query_parser.get('dealership', '_get_dealership_by_id').format(id))
        _user_id = get_jwt_identity()
        try:
            # TODO Existing _get_dealership_by_user_id should have role mapping with product and needs to be
            # replaced with _get_dealership_by_user_role_id_with_product_map
            _result = mydb.run_query(mydb.SELECT,
                                     query_parser.get('users', '_get_role_product_map_count').format(_user_id))
            if _result:
                if int(_result[0]['row_count']) > 0:
                    return _get_result(
                        query_parser.get('dealership', '_get_dealership_by_user_role_id_with_product_map').format(
                            _user_id))
        except Exception as e:
            logger.error(
                'Error while querying data using _get_dealership_by_user_role_id_with_product_map-> {}'.format(e))
        return _get_result(query_parser.get('dealership', '_get_dealership_by_user_id').format(_user_id))
    elif request.method == 'DELETE':
        data = request.get_json()
        if data.get('type'):
            col_name = get_column_by_file_type(data.get('type'))
        else:
            col_name = list(data)[0]
        mydb.run_query(mydb.DELETE,
                       query_parser.get('dealership', '_remove_dealership_attachment').format(col_name, id))
        return jsonify({"status": "SUCCESS", "message": "Attachment removed successfully."})


def format_date_in_data(data, field_list):
    for field in field_list:
        _value = data.get(field)
        if _value and _value != "null" and _value != "NULL" and _value != "undefined":
            data.update({field: datetime.datetime.strptime(_value, "%d-%m-%Y").strftime("%Y-%m-%d")})
    return data


@app.route('/api/assigned/dealership/<int:fo_id>', methods=['GET'])
@jwt_required
def _get_assigned_dealership(fo_id=None):
    return _get_result(query_parser.get('dealership', '_get_all_dealership_fo').format(fo_id))


@app.route('/api/dealership/<int:dealership_id>/business/details', methods=['GET', 'POST'])
def _business_details_dealership(dealership_id=None):
    if dealership_id:
        if request.method == 'GET':
            return _get_result(query_parser.get('dealership', '_get_business_details').format(dealership_id))
        elif request.method == 'POST':
            data = request.get_json()
            data.update({"dealership_id": dealership_id})
            col_list = mydb._get_columns("t_business_details")
            query = mydb._gen_upsert_query("t_business_details", col_list, data)
            return _is_rows_affected(query, True, 4, dealership_id)
    else:
        return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_id_not_found')})


@app.route('/api/dealership/<int:dealership_id>/referral', methods=['GET', 'POST'])
@app.route('/api/dealership/<int:dealership_id>/referral/<int:id>', methods=['POST'])
@app.route('/api/dealership/referral', methods=['GET'])
@jwt_required
def _dealer_referral(dealership_id=None, id=None):
    if request.method == 'POST':
        data = request.get_json()
        if id:
            if data.get('referred_dealership_id'):
                check_loan_status = _get_result_as_dict(
                    query_parser.get('dealership', '_get_dealership_loan_details').format(
                        data.get('referred_dealership_id')))[0]
                bonus_amount = check_loan_status.get('amount_disbursed') * 0.0075
                data.update({'last_modified_by': get_jwt_identity(),
                             'bonus_amount': bonus_amount})
            query = mydb._gen_update_query("t_dealership_referral", mydb._get_columns("t_dealership_referral"), data)
            return _execute_query(mydb.UPDATE, query + " WHERE id={0}".format(id))
        else:
            _dealer_data = \
            _get_result_as_dict(query_parser.get('dealership', '_get_dealership_by_id').format(dealership_id))[0]
            check_loan_status = _get_result_as_dict(
                query_parser.get('dealership', '_get_dealership_loan_details').format(
                    data.get('referred_dealership_id')))[0]
            bonus_amount = check_loan_status.get('amount_disbursed') * 0.0075
            data.update({'dealership_id': dealership_id,
                         'dealership_name': _dealer_data.get('name'),
                         'dealership_region': _dealer_data.get('region_name'),
                         'bonus_amount': bonus_amount,
                         'created_by': get_jwt_identity(),
                         'last_modified_by': get_jwt_identity()})
            query = mydb._gen_insert_query("t_dealership_referral", data)
            return _execute_query(mydb.INSERT, query)
    if request.method == 'GET':
        if dealership_id:
            result = _get_result_as_dict(
                query_parser.get('dealership', '_get_dealership_referral') + " WHERE dealership_id={0}".format(
                    dealership_id))
            if not result:
                return jsonify({'status': 'ERROR', 'message': 'No data found for the provided dealership id.'})
            return jsonify({'status': 'SUCCESS', 'data': result})
        else:
            result = _get_result_as_dict(
                query_parser.get('dealership', '_get_dealership_referral'))
            if not result:
                return jsonify({'status': 'ERROR', 'message': 'No dealership referral data found.'})
            return jsonify({'status': 'SUCCESS', 'data': result})



@app.route('/api/dealership/<int:dealership_id>/credit/info', methods=["POST", "GET"])
@jwt_required
def _credit_info(dealership_id=None):
    if dealership_id:
        if request.method == 'POST':
            data = request.get_json()
            data.update({"dealership_id": dealership_id, "last_modified_by": get_jwt_identity()})
            col_list = ["dealership_id", "dealer_id", "cibil_score", "loans_count", "closed_loans_count",
                        "od_accounts_count", "od_amount", "current_os_amount", "cibil_vintage", "no_of_enquiries",
                        "is_loan_in_bureau", "highest_dpd", "highest_dpd_bracket", "is_cc_in_cibil", "status",
                        "last_modified_by"]
            if data.get('id'):
                query = mydb._gen_update_query("t_dealership_applicants_credit_info", col_list, data)
                return _execute_query_with_status(mydb.UPDATE, query + " WHERE id={}".format(data.get('id')), True, 10,
                                                  dealership_id)
            else:
                query = mydb._gen_insert_query_exclude_cols("t_dealership_applicants_credit_info", col_list, data)
                return _execute_query_with_status(mydb.INSERT, query, True, 10, dealership_id)
        elif request.method == 'GET':
            _applicant_types = ['m_dealers', 't_dealers_coapplicants', 't_dealership_guarantors']
            _query = query_parser.get('mdm_credit', '_get_credit_info')
            _credit_info = []
            for applicant in _applicant_types:
                _applicant_data = _get_result_as_dict(_query.format(applicant.split('_')[-1], applicant) +
                                                      " WHERE d.dealership_id={} and d.is_active=1 and dac.is_current = 1 order by dac.modified_date desc".format(
                                                          dealership_id))
                _credit_info.extend(_applicant_data)
            return jsonify({'status': 'SUCCESS', 'data': _credit_info})
    else:
        return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_invalid_request')})

@app.route('/api/dealership/<int:dealership_id>/income/details', methods=['GET', 'POST'])
@jwt_required
def _get_income_details_dealership(dealership_id=None):
    if dealership_id:
        if request.method == 'GET':
            return _get_result(query_parser.get('dealership', '_get_income_details').format(dealership_id))
        elif request.method == 'POST':
            data = request.get_json()
            data.update({"dealership_id": dealership_id, "last_modified_by": get_jwt_identity()})
            query = mydb._gen_insert_query("t_dealership_other_income", data)
            return _is_rows_affected(query, True, 5, dealership_id)
        else:
            return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_invalid_request')})
    else:
        return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_id_not_found')})


@app.route('/api/dealership/income/details/<int:income_id>', methods=['POST', 'DELETE'])
@jwt_required
def _update_other_income_details_dealership(income_id=None):
    if income_id:
        if request.method == 'POST':
            data = request.get_json()
            data.update({"last_modified_by": get_jwt_identity()})
            cols = mydb._get_columns("t_dealership_other_income")
            query = mydb._gen_update_query("t_dealership_other_income", cols, data)
            return _is_rows_affected(query + " WHERE id = {}".format(income_id))
        elif request.method == 'DELETE':
            query = query_parser.get('dealership', '_remove_income').format(income_id)
            return _execute_query(mydb.DELETE, query, "Income detail removed successfully",
                                  "Delete request unsuccessful")
        else:
            return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_invalid_request')}), 200
    else:
        return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_id_not_found')}), 200


@app.route('/api/dealership/<int:dealership_id>/expense/details', methods=['GET', 'POST'])
@jwt_required
def _get_expense_details_dealership(dealership_id=None):
    if dealership_id:
        if request.method == 'GET':
            return _get_result(query_parser.get('dealership', '_get_expense_details').format(dealership_id))
        elif request.method == 'POST':
            data = request.get_json()
            data.update({"dealership_id": dealership_id, "last_modified_by": get_jwt_identity()})
            query = mydb._gen_insert_query("t_dealership_other_expense", data)
            return _is_rows_affected(query, True, 5, dealership_id)
        else:
            return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_invalid_request')}), 200
    else:
        return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_id_not_found')}), 200


@app.route('/api/dealership/expense/details/<int:expense_id>', methods=['POST', 'DELETE'])
@jwt_required
def _update_other_expense_details_dealership(expense_id=None):
    if expense_id:
        if request.method == 'POST':
            data = request.get_json()
            data.update({"last_modified_by": get_jwt_identity()})
            cols = mydb._get_columns("t_dealership_other_expense")
            query = mydb._gen_update_query("t_dealership_other_expense", cols, data)
            return _is_rows_affected(query + " WHERE id = {}".format(expense_id))
        elif request.method == 'DELETE':
            query = query_parser.get('dealership', '_remove_expense').format(expense_id)
            return _execute_query(mydb.DELETE, query, "Expense detail removed successfully",
                                  "Delete request unsuccessful")
        else:
            return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_invalid_request')}), 200
    else:
        return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_id_not_found')}), 200


@app.route('/api/dealership/<int:dealership_id>/assets', methods=['GET', 'POST'])
@app.route('/api/dealership/<int:dealership_id>/assets/<int:id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def _get_asset_details_dealership(dealership_id=None, id=None):
    if request.method == 'GET':
        query = query_parser.get('dealership', '_get_asset_details')
        if dealership_id and id:
            query += " WHERE t.id='{0}'".format(id)
        else:
            query += " WHERE t.dealership_id='{0}'".format(dealership_id)
        return _get_result(query)
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"dealership_id": dealership_id, "last_modified_by": get_jwt_identity()})
        data.update({"details": json.dumps(data.get('details'))})
        if dealership_id and id:
            cols = mydb._get_columns("t_dealership_assets")
            query = mydb._gen_update_query("t_dealership_assets", cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id={0}".format(id))
        else:
            query = mydb._gen_insert_query("t_dealership_assets", data)
            return _is_rows_affected(query, True, 6, dealership_id)
    elif request.method == 'DELETE':
        return _is_rows_affected(query_parser.get('dealership', '_delete_asset_details_by_id').format(id))


@app.route('/api/dealership/collection/remarks', methods=['GET', 'POST'])
@app.route('/api/dealership/<prospect_code>/collection/remarks', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def _get_collection_remarks_dealership(prospect_code=None):
    if request.method == 'GET':
        query = query_parser.get('dealership', '_get_all_collection_remarks')
        options = query_parser.get('remarks', '_get_collection_remarks_options')
        if prospect_code:
            query += " WHERE prospect_code='{0}'".format(prospect_code)
        remarks_data = _get_result_as_dict(query + " ORDER BY created_date DESC")
        options_data = _get_result_as_dict(options)
        for remark in remarks_data:
            if remark.get('details'):
                _details = json.loads(remark.get('details'))
                remark.update({"details": _details})
                _options_list = []
            for option in options_data:
                if remark.get('remarks_id') == option.get('remarks_id'):
                    _options_list.append(option)
                    remark.update({"options": _options_list})
        return jsonify({"status": "SUCCESS", "data": remarks_data})
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity()})
        if prospect_code:
            cols = mydb._get_columns("t_loan_collection_remarks")
            query = mydb._gen_update_query("t_loan_collection_remarks", cols, data)
            query += " WHERE prospect_code='{0}'".format(prospect_code)
        else:
            query = mydb._gen_insert_query("t_loan_collection_remarks", data)
        return _execute_query(mydb.INSERT, query)
    elif request.method == 'DELETE':
        return _is_rows_affected(
            query_parser.get('dealership', '_delete_collection_remarks_details').format(prospect_code))


@app.route('/api/dealership/<int:dealership_id>/bank/<int:bank_id>', methods=['POST', 'DELETE'])
@app.route('/api/dealership/<int:dealership_id>/bank', methods=['GET', 'POST'])
@jwt_required
def _get_bank_details_dealership(dealership_id=None, bank_id=None):
    if request.method == 'GET':
        return _get_result(query_parser.get('dealership', '_get_bank_details').format(dealership_id))
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity(), "dealership_id": dealership_id})
        cols = mydb._get_columns("t_dealership_bank_details")
        if bank_id:
            query = mydb._gen_update_query("t_dealership_bank_details", cols, data)
            query += " where id = {}".format(bank_id)
            return _execute_query(mydb.UPDATE, query)
        else:
            query = mydb._gen_insert_query_exclude_cols("t_dealership_bank_details", cols, data)
            return _execute_query(mydb.INSERT, query)
    elif request.method == 'DELETE':
        return _execute_query(mydb.DELETE,
                              query_parser.get('dealership', '_remove_bank_details')
                              .format(bank_id))


@app.route('/api/application/state', methods=['GET'])
@jwt_required
def get_application_state():
    _application = mydb.run_query(mydb.SELECT, query_parser.get('dealership', '_get_all_application'))
    return jsonify({"status": "SUCCESS", "data": _application})


@app.route('/api/dealership/<int:dealership_id>/loans', methods=['GET', 'POST'])
@app.route('/api/dealership/<int:dealership_id>/loans/<int:loan_id>', methods=['GET', 'POST', 'DELETE'])
def _dealership_loan_details(dealership_id=None, loan_id=None):
    if dealership_id:
        if loan_id:
            if request.method == 'POST':
                data = request.get_json()
                _get_current_loan_status = mydb.run_query(mydb.SELECT,
                                                          "SELECT status from t_dealership_loans WHERE id = {}".format(
                                                              loan_id))
                now = datetime.datetime.now()
                if (data.get('status') == "approved" and (
                        _get_current_loan_status[0].get('status')).lower() == "submitted"):
                    data.update({'loan_approved_rejected_date': now.strftime('%Y-%m-%d %H:%M:%S')})
                elif data.get('status') == "disbursed" and _get_current_loan_status[0].get('status') == "approved":
                    data.update({'loan_disbursed_date': now.strftime('%Y-%m-%d %H:%M:%S')})
                elif data.get('status') == "disbursed" and _get_current_loan_status[0].get('status') == "submitted":
                    return jsonify(error_parser.get('invalid', '_incorrect_loan_process')), 200
                cols = mydb._get_columns("t_dealership_loans")
                query = mydb._gen_update_query("t_dealership_loans", cols, data)
                return _is_rows_affected(
                    query + ", remarks=CONCAT(remarks, '{0}') WHERE id = {1} AND dealership_id = {2}".format(
                        data.get('remarks'), loan_id, dealership_id), True, 3, dealership_id)
            elif request.method == 'DELETE':
                return _is_rows_affected(
                    query_parser.get('dealership', '_remove_loan_details').format(loan_id, dealership_id), False, 3,
                    dealership_id)
            elif request.method == 'GET':
                loan_data = mydb.run_query(mydb.SELECT,
                                           query_parser.get('dealership', '_get_loan_details_by_id').format(loan_id,
                                                                                                            dealership_id))
                loan_disbursed_details_data = mydb.run_query(mydb.SELECT,
                                                             query_parser.get('dealership',
                                                                              '_get_loan_disbursement_details').format(
                                                                 loan_id))
                for key, value in groupby(loan_disbursed_details_data, key=itemgetter('applicant_code')):
                    result = {}
                    result.update({'applicant_code': key})
                    details = []
                    for i in value:
                        details.append(i)
                    result.update({'disbursement_details': details})
                    loan_data[0].update(result)
                return jsonify({"status": "SUCCESS", "data": loan_data})
            else:
                return jsonify(error_parser.get('invalid', '_invalid_request')), 200
        else:
            if request.method == 'POST':
                if _dealership_loan_exists(dealership_id):
                    return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_loan_exists')})
                else:
                    data = request.get_json()
                    data.update({'dealership_id': dealership_id})
                    _query = mydb._gen_insert_query('t_dealership_loans', data)
                    return _execute_query_with_status(mydb.INSERT, _query, True, 3, dealership_id)
            elif request.method == 'GET':
                return _get_result(query_parser.get('dealership', '_get_dealership_loan_details').format(dealership_id))
    else:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_id_not_found')})


@app.route('/api/loans/renewal', methods=['GET'])
@jwt_required
def loans_renewal():
    "This api is used to get withheld renewal loans"
    if request.method == 'GET':
        query = query_parser.get('renewal', '_get_renewal_loans')
        _result = mydb.run_query(mydb.SELECT, query)
        return jsonify({"status": "SUCCESS", "data": _result})


@app.route('/api/dealership/<int:dealership_id>/operators', methods=['POST', 'GET'])
@app.route('/api/dealership/<int:dealership_id>/operators/<int:id>', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def _fleet_operators(id=None, dealership_id=None):
    if request.method == 'POST':
        data = request.get_json()
        data.update({'dealership_id': dealership_id})
        if id:
            cols = mydb._get_columns('t_fleet_operators')
            _query = mydb._gen_update_query('t_fleet_operators', cols, data) + ' where id ={}'.format(id)
            result = mydb.run_query(mydb.UPDATE, _query)
            return jsonify({"status": "SUCCESS", "message": "Updated successfully.", "result": result})
        else:
            return _execute_query(mydb.INSERT, mydb._gen_insert_query('t_fleet_operators', data))
    elif request.method == 'GET':
        if id:
            return _get_result(
                query_parser.get('dealership_transporter', '_get_fleet_operators_by_id').format(id))
        else:
            return _get_result(
                query_parser.get('dealership_transporter', '_get_fleet_operators_by_dealership_id').format(
                    dealership_id))
    elif request.method == 'DELETE':
        _query = query_parser.get('dealership_transporter', '_del_fleet_operators_by_id').format(id)
        result = mydb.run_query(mydb.DELETE, _query)
        return jsonify({"status": "SUCCESS", "message": "Removed successfully.", "result": result})


@app.route('/api/loans', methods=['GET'])
@jwt_required
def _get_all_loans():
    status = request.args.get('status')
    if status and status != '':
        query, page, row_count = _get_loan_stats(args=request.args, user_id=get_jwt_identity())
        data = mydb.run_query(mydb.SELECT, query)
        if request.args.get('download', 0):
            df = pd.DataFrame.from_dict(data)
            table_data = base64.b64encode(df.to_csv(index=False).encode())
            csv_file = table_data.decode('ascii')
            return jsonify({"status": "SUCCESS", "base64_encoded": csv_file})
        if request.args.get('pagination', 0):
            return jsonify({'status': 'SUCCESS', "data": data, "page": page, "row_count": row_count})
        return jsonify({'status': 'SUCCESS', 'data': data})
    else:
        query = (query_parser.get('dealership', '_get_all_loans'))
        return _get_result(query)



def _split(data=None):
    if data:
        data = data.split(',')
        return str(data).replace("[", "(").replace("]", ")")
    return data


@app.route('/api/loans/exceptions', methods=['GET'])
@jwt_required
def _map_lms_with_los():
    return jsonify(
        {"status": "SUCCESS", "data": _lms_data_handler('loans_ext','_loans_exception')})


def _is_remarks_exist(dealership_id, remarks_id):
    if remarks_id:
        _is_remark_exist = query_parser.get('withheld', '_is_remarks_exist_with_dealership_id').format(dealership_id,
                                                                                                       remarks_id)
        result = mydb.run_query(mydb.SELECT, _is_remark_exist)
        if result:
            return result[0].get("is_resolved")


def date_validation(df, i_loc):
    temp = str(df.iloc[i_loc].get('transactionDateTime')).replace(':', ' ').replace('-', ' ').replace('/', ' ').split(
        ' ')
    value = [str(i) for i in list(df.iloc[i_loc])]
    try:
        temp = [int(i) for i in temp]
        if len(temp) == 6:
            value[list(df).index('transactionDateTime')] = datetime.datetime(*temp).strftime("%Y-%m-%d %H:%M:%S")
        elif len(temp) == 5:
            value[list(df).index('transactionDateTime')] = datetime.datetime(*temp).strftime("%Y-%m-%d %H:%M")
        return True, tuple(value)
    except:
        pass
    try:
        temp[0], temp[2] = temp[2], temp[0]
        if len(temp) == 6:
            value[list(df).index('transactionDateTime')] = datetime.datetime(*temp).strftime("%Y-%m-%d %H:%M:%S")
        elif len(temp) == 5:
            value[list(df).index('transactionDateTime')] = datetime.datetime(*temp).strftime("%Y-%m-%d %H:%M")
        return True, tuple(value)
    except:
        return False, i_loc


def _upload_to_db_(data):
    _query = "INSERT into t_fastag(" + ",".join(list(data)) + ") values (" + ",".join(["%s" for i in list(data)]) + ")"
    values = []
    skip = []
    for i in range(len(data)):
        flag, row = date_validation(data, i)
        if flag:
            values.append(row)
        else:
            skip.append(str(row + 2))
    _is_insert, _error = mydb._bulk_insert(_query, values)
    if _is_insert:
        if len(skip) == 0:
            return jsonify({'status': 'SUCCESS', 'message': "Successfully Uploaded to Database"})
        return jsonify({'status': 'SUCCESS',
                        'message': "Total Number of records = {0} Number of uploaded records = {1} \n"
                                   "Total Number of Skipped records = {2} \n "+_support_message
                       .format(len(data), len(values), len(skip), ",".join(skip))})
    else:
        if _error.args[0] == 1062:
            return jsonify({'status': 'ERROR', 'message': _error.args[1].split("'")[0] + "row_id = " + "".join(
                [str(values.index(i) + 1) for i in values if
                 _error.args[1].split("'")[1] in i]) + " Kindly remove existing record and upload again."})
        return jsonify({'status': 'ERROR', 'message': 'Unable to upload Database'})


def get_transporter_email(key, value):
    _get_transporter_email = query_parser.get('transporters', '_get_transporter_email') + " AND {0}='{1}'".format(key,
                                                                                                                  value)
    return _get_result_as_dict(_get_transporter_email)


@app.route('/api/fastag/upload/statement', methods=['POST'])
@app.route('/api/fastag/details', methods=['GET'])
@app.route('/api/fastag/search', methods=['GET'])
@jwt_required
def fastag_statement_upload():
    if request.method == 'POST':
        if request.files:
            file = request.files.get('file')
            _extension = file.filename.split('.')[-1].lower()
            if allowed_file(file.filename, extensions={'xls', 'xlsx', 'csv'}):
                file_name = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
                if _extension == 'csv':
                    data = pd.read_csv(file)
                else:
                    data = pd.read_excel(file)
                    file_path = file_path.replace('xlsx', 'csv').replace('xls', 'csv')
                    file_name = file_name.replace('xlsx', 'csv').replace('xls', 'csv')
                data.to_csv(file_path, encoding='utf-8', index=False)
                file = open(file_path)
                _s3_file_prefix = str('fastag') + '/' + datetime.datetime.today().strftime('%Y-%m-%d')
                _upload_status, _uploaded_file = _s3_file_upload("transporters/" + _s3_file_prefix, file_name,
                                                                 transporter_docs_bucket, file)
                file.close()
                if not _upload_status:
                    return jsonify(
                        {"status": "ERROR", "message": "File could not be uploaded to S3. Please try again."})
                os.remove(file_path)
                return _upload_to_db_(data)
            else:
                return jsonify({'status': 'ERROR',
                                'message': 'Invalid file format. Accepted file types are .csv, .xls and .xlsx only.'})
        else:
            return jsonify({'status': 'ERROR', 'message': 'File is empty'})
    if request.method == 'GET':
        if 'search' in str(request.base_url):
            if request.args.get('vehicle', 0):
                query = query_parser.get('fastag', '_get_vehicle_registration_no').format(request.args.get('vehicle'))
                if request.args.get('owner_id'):
                    query += " AND t.t_owner_id='{0}'".format(request.args.get('owner_id'))
                elif request.args.get('transport_code'):
                    query += " AND v.transporter_id='{0}'".format(request.args.get('transport_code'))
                if _get_user_role(get_jwt_identity()) == 14:
                    query += " AND t.t_owner_id={0}".format(get_jwt_identity())
            elif request.args.get('id', 0):
                query = query_parser.get('fastag', '_get_transporter_id').format(request.args.get('id'))
                if _get_user_role(get_jwt_identity()) == 14:
                    query += " AND t_owner_id={0}".format(get_jwt_identity())
            else:
                return jsonify({'status': 'ERROR', 'message': 'Invalid Arguments'})
            return _get_result(query + " LIMIT 50")
        if request.args.get('pagination', 0):
            row_count = mydb.run_query(mydb.SELECT, query_parser.get('fastag', '_get_count'))[0].get('count', 0)
            page = 0
        else:
            row_count = int(request.args.get('row_count', 15))
            page = int(request.args.get('page', 0)) * row_count
        _from = request.args.get('from', datetime.date.today() - datetime.timedelta(days=6))
        _to = request.args.get('to')
        if _to:
            _to = datetime.datetime.strptime(_to, "%Y-%m-%d") + datetime.timedelta(days=1)
            _to = _to.date()
        else:
            _to = datetime.date.today() + datetime.timedelta(days=1)
        search_key = {}
        if request.args.get('vehicle'):
            _get_vehicle_data = query_parser.get('fastag', '_get_data').format('vehicleRegistrationNo',
                                                                               request.args.get('vehicle'), _from, _to,
                                                                               page, row_count)
            _data = mydb.run_query(mydb.SELECT, _get_vehicle_data)
            _get_summary = mydb.run_query(mydb.SELECT,
                                          query_parser.get('fastag', '_get_summary').format('vehicleRegistrationNo',
                                                                                            request.args.get('vehicle'),
                                                                                            _from, _to))
            search_key.update({'tt_no': request.args.get('vehicle')})

        elif request.args.get('id'):
            _transport_data = query_parser.get('fastag', '_get_data').format('transporter_id', request.args.get('id'),
                                                                             _from, _to, page, row_count)
            _data = mydb.run_query(mydb.SELECT, _transport_data)
            _get_summary = mydb.run_query(mydb.SELECT,
                                          query_parser.get('fastag', '_get_summary').format('transporter_id',
                                                                                            request.args.get('id'),
                                                                                            _from, _to))
            search_key.update({'t.transporter_id': request.args.get('id')})

        else:
            return jsonify({'status': 'ERROR', 'message': 'Missing required arguments.'})

        if request.args.get('send', 0):
            _data = pd.DataFrame(_data)
            if len(_data):
                transaction_count = _get_summary[0].get('count', 0)
                total_amount = _get_summary[0].get('total_amount', 0)
                total_vehicle = _get_summary[0].get('total_vehicles', 0)
                if request.args.get('id'):
                    file_content = """"From","To",Transactions,Total Amount,Total Vehicles," "\n{0},{1},{2},{3},{4}," "\n""".format(
                        _from, _to - datetime.timedelta(days=1), transaction_count, total_amount, total_vehicle)
                else:
                    file_content = """"From","To",Transactions,Total Amount," "," "\n{0},{1},{2},{3}," "," "\n""".format(
                        _from, _to - datetime.timedelta(days=1), transaction_count, total_amount)
                file_content += _data.to_csv(index=False)
                file_name = secure_filename(datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S') + ".csv")
                file = open("data/" + file_name, 'w')
                file.write(file_content.replace('\r', ''))
                file.close()
                file = open("data/" + file_name)
                if request.args.get('download', 0):
                    _s3_file_prefix = "transporters/" + str('fastag') + '/' + str('report') + '/' + str(
                        get_jwt_identity())
                    _upload_status, _uploaded_file = _s3_file_upload(_s3_file_prefix,
                                                                     file_name,
                                                                     transporter_docs_bucket,
                                                                     file)
                    file.close()
                    os.remove("data/" + file_name)
                    if _upload_status:
                        return jsonify({'status': 'SUCCESS', 'data': [_uploaded_file]})
                    else:
                        return jsonify({'status': 'ERROR', 'message': 'Unable to Download data'})
                mail = {}
                transporter_details = get_transporter_email(*list(search_key.items())[0])
                if transporter_details:
                    transporter_details = transporter_details[0]
                    if transporter_details.get('email'):
                        mail.update({'subject': 'Petromoney Fastag report',
                                     'body': """Dear Customer,\nGreetings from Petromoney!\nPlease find attached e-Statement of your Fastag usage as requested.\nThanks,\nTeam Petromoney""",
                                     'recipients': [transporter_details.get('email')],
                                     'cc': carbon_copy_list
                                     })
                        file_to_attach = [file.name]
                        file_names = [file_name]
                        mail_status = _send_mail(mail, attachment=file_to_attach, file_name=file_names,
                                                 file_type="text/csv")
                        file.close()
                        os.remove("data/" + file_name)
                        if mail_status.get_json().get('delivery'):
                            return jsonify({'status': 'SUCCESS', 'message': 'Mail sent successfully.'})
                return jsonify({'status': 'ERROR', 'message': "Unable to send mail."})
            else:
                return jsonify({'status': 'ERROR', 'message': 'No transaction available.'})
        _get_summary = _get_summary[0]
        return jsonify({'status': 'SUCCESS',
                        'data': {"list": _data, "count": _get_summary.get('count'),
                                 "page": page // row_count,
                                 "total_vehicles": str(_get_summary.get('total_vehicles')),
                                 "total_amount": str(_get_summary.get('total_amount'))}})


@app.route('/api/dealership/<int:dealership_id>/withheld/loans', methods=['POST'])
@app.route('/api/withheld/loans', methods=['GET'])
@app.route('/api/withheld/loans/<int:id>', methods=['POST', 'DELETE'])
@jwt_required
def withheld_loans(dealership_id=None, id=None):
    if request.method == "POST":
        data = request.get_json()
        if id:
            return _execute_query(mydb.UPDATE, mydb._gen_update_query('t_withheld_loans', list(data),
                                                                      data) + " WHERE id='{}'".format(id),
                                  success_message="Withheld loan is released.",
                                  fail_message="Loan unresolved."+_support_message)
        else:
            remarks_id = data.get('remarks_id')
            is_resolved = _is_remarks_exist(dealership_id, remarks_id)
            if is_resolved == 0:
                return jsonify({'status': 'ERROR', 'message': 'This remarks is already assigned to the dealership'})
            if data.get('remarks'):
                cols = mydb._get_columns('m_remarks')
                insert_new_remarks = mydb._gen_insert_query_exclude_cols('m_remarks', cols, data)
                res, remarks_id = mydb.run_query(mydb.INSERT, insert_new_remarks, row_insert_id=True)
            comment = data.pop('comment')
            _add_remarks_qry = ''
            if comment:
                if len(comment) > 300:
                    return jsonify({'status': 'ERROR', 'message': 'Comments has to be less than 300 words.'})
                _add_remarks_qry = query_parser.get('withheld', '_insert_remarks_comment').format(dealership_id,
                                                                                                  remarks_id,
                                                                                                  comment)
            else:
                _add_remarks_qry = query_parser.get('withheld', '_insert_remarks_').format(dealership_id, remarks_id)
            if _add_remarks_qry:
                return _execute_query(mydb.INSERT, _add_remarks_qry, success_message="Remarks added successfully.",
                                      fail_message="Failed to add remarks.")

    if request.method == 'DELETE':
        delete_remarks = query_parser.get('withheld', '_delete_remarks').format(id)
        return _execute_query(mydb.DELETE, delete_remarks, success_message="Remarks deleted successfully.",
                              fail_message="Failed to delete remarks.")
    if request.method == 'GET':
        if request.args.get('is_resolved'):
            _withheld_loans = _get_result_as_dict(
                query_parser.get('withheld', '_get_withheld_loans').format(request.args.get('is_resolved')))
            for i in _withheld_loans:
                try:
                    i.update({'remarks': json.loads(i.get('remarks'))})
                except ValueError as ve:
                    logger.error("Couldn't parse remarks because : {}".format(ve))
                    return jsonify({'status': 'ERROR', 'message': 'Unable to fetch remarks. '+_support_message})
            return jsonify({'status': 'SUCCESS', 'data': _withheld_loans})
        return jsonify({'status': 'ERROR', 'message': 'Missing required key.'})


def _get_id_by_key(data, key, table_name, column_in_table='name'):
    value = str(data.get(key))
    if value and not value.isnumeric():
        _result = _get_result_as_dict(
            query_parser.get('general', '_get_id_by_given_key').format(table_name, column_in_table, value))
        if _result:
            data.update({key: _result[0].get('id')})
    return data


@app.route('/api/dealers/<int:dealership_id>', methods=['GET', 'POST'])
@app.route('/api/dealers/<int:dealership_id>/<int:id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def _dealers(dealership_id=None, id=None):
    data = {}
    if request.method == 'POST':
        data = format_date_in_data(encrypt_data(dict(request.form)), ['dob'])
        data.update({"dealership_id": dealership_id})
        data.update({"last_modified_by": get_jwt_identity()})
        data = _get_id_by_key(data, 'state', 'm_states')
        data = _get_id_by_key(data, 'city', 'm_cities')
        if _check_duplicates("m_dealers", data, applicant_id=id):
            return jsonify({"status": "ERROR", "message": "Duplicate KYC records (Aadhar/PAN/Mobile)"})
    if request.files:
        _status_, result = _upload_kyc_docs(request.files, origin_id=dealership_id, id=id, type='dealers')
        if _status_:
            data.update(result)
        else:
            return jsonify({'status': 'ERROR', 'message': result})
    _col_list = mydb._get_columns('m_dealers')
    if id:
        if request.method == 'POST':
            check_is_main_applicant_query = query_parser.get(
                'dealers', '_get_dealer_mainapplicant') + ' and m.dealership_id= {1}'
            check_is_main_applicant = _get_result_as_dict(check_is_main_applicant_query.format(id, dealership_id))[0]
            if check_is_main_applicant.get('is_main_applicant'):
                _data = {}
                a = {d: data.get(d) for d in USER_MAINAPPLICANT_FIELDS if data.get(d)}
                _data.update(a)
                _users_col_list = mydb._get_columns('m_users')
                _query = mydb._gen_update_query(
                    "m_users", _users_col_list, _data)
                _execute_query(mydb.UPDATE, _query + " WHERE mobile ='{0}' ".format(
                    check_is_main_applicant.get('mobile')))
            data.update({"id": id})
            query = mydb._gen_update_query("m_dealers", _col_list, data)
            return _is_rows_affected(query + " WHERE id=" + str(id), True, 2, dealership_id)
        elif request.method == 'GET':
            dealer_details = query_parser.get('dealers', '_get_dealers_id').format(id)
            return _get_result(dealer_details)
        elif request.method == 'DELETE':
            data = request.get_json()
            mydb.run_query(mydb.DELETE, mydb._gen_update_query('m_dealers', list(data),
                                                               data) + " WHERE dealership_id={0} AND id={1}".format(
                dealership_id, id))
            return jsonify({"status": "SUCCESS", "message": "User or attachment removed successfully."})
    else:
        if request.method == 'POST':
            """ This is for the PROD issue fix, it will be changed. """
            main_applicant = _is_main_applicant(data.get('mobile'), dealership_id)
            if main_applicant:
                data.update({"is_main_applicant": "0"})
                logger.debug("Mobile number already exists.")
            else:
                data.update({"is_main_applicant": "1"})
            if data.get(data.get('id')):
                check_is_main_applicant_query = query_parser.get(
                    'dealers', '_get_dealer') + ' and m.dealership_id= {1}'
                check_is_main_applicant = _get_result_as_dict(
                    check_is_main_applicant_query.format(data.get('id'), dealership_id))[0]
                if check_is_main_applicant.get('is_main_applicant'):
                    _data = {}
                    _user_data = {key: data.get(key) for key in USER_MAINAPPLICANT_FIELDS if data.get(key)}
                    _data.update(_user_data)
                    _users_col_list = mydb._get_columns('m_users')
                    _query = mydb._gen_update_query(
                        "m_users", _users_col_list, _data)
                    _execute_query(mydb.UPDATE, _query + " WHERE mobile ='{0}' ".format(
                        check_is_main_applicant.get('mobile')))
            insert_dealer_data = mydb._gen_insert_query_exclude_cols("m_dealers", _col_list, data)
            return _is_rows_affected(insert_dealer_data, True, 2, dealership_id)
        elif request.method == 'GET':
            _active_dealers = _get_result_as_dict(
                query_parser.get('dealers', '_get_associated_dealers').format(dealership_id))
            if _get_user_role(get_jwt_identity()) == 1:
                """
                if login user is Admin show active and inactive dealers,
                else, show active dealers only
                """
                if not _active_dealers:
                    _active_dealers = []
                _inactive_dealers = _get_result_as_dict(
                    query_parser.get('dealers', '_get_associated_inactive_dealers').format(dealership_id))
                if not _inactive_dealers:
                    _inactive_dealers = []
                return jsonify({"status": "SUCCESS", "data": _active_dealers + _inactive_dealers})
            return jsonify({"status": "SUCCESS", "data": _active_dealers})


@app.route('/api/coapplicants', methods=['GET'])
@app.route('/api/coapplicants/<int:dealership_id>', methods=['GET', 'POST'])
@app.route('/api/coapplicants/<int:dealership_id>/<int:id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def _dealer_co_applicants(dealership_id=None, id=None):
    if request.method == 'POST':
        data = format_date_in_data(encrypt_data(dict(request.form)), ['dob'])
        data.update({"last_modified_by": get_jwt_identity(), "dealership_id": dealership_id})
        data = _get_id_by_key(data, 'state', 'm_states')
        data = _get_id_by_key(data, 'city', 'm_cities')

        """
        CoApplicants can be present in more than one dealerships so checking for duplicate KYC is not needed
        """
        # if _check_duplicates("t_dealers_coapplicants", data, applicant_id=id):
        #     return jsonify({"status":"ERROR","message":"Duplicate KYC records (Aadhar/PAN/Mobile)"})

        if request.files is not None:
            _status_, result = _upload_kyc_docs(request.files, origin_id=dealership_id, id=id, type='dealers')
            if _status_:
                data.update(result)
            else:
                return jsonify({'status': 'ERROR', 'message': result})
    col_list = mydb._get_columns('t_dealers_coapplicants')
    if id:
        if request.method == 'POST':
            query = mydb._gen_update_query('t_dealers_coapplicants', col_list, data)
            return _is_rows_affected(query + " WHERE id={}".format(id), True, 8, dealership_id)
        elif request.method == 'GET':
            dealer_details = query_parser.get('coapplicants', '_get_coapplicant_by_id').format(id)
            return _get_result(dealer_details)
        elif request.method == 'DELETE':
            data = request.get_json()
            mydb.run_query(mydb.DELETE,
                           mydb._gen_update_query('t_dealers_coapplicants', list(data), data) + " WHERE id={0}".format(
                               id))
            return jsonify({"status": "SUCCESS", "message": "User or attachment removed successfully."})
    else:
        if request.method == 'POST':
            query = mydb._gen_insert_query_exclude_cols(
                "t_dealers_coapplicants", col_list, data)
            return _is_rows_affected(query, True, 8, dealership_id)
        elif request.method == 'GET':
            if dealership_id:
                _active_coapplicant = _get_result_as_dict(query_parser.get(
                    'coapplicants', '_get_associated_coapplicants').format(dealership_id))
                if _get_user_role(get_jwt_identity()) == 1:
                    """
                    if login user is Admin show active and inactive coapplicants,
                    else, show active coapplicants only
                    """
                    if not _active_coapplicant:
                        _active_coapplicant = []
                    _inactive_coapplicant = _get_result_as_dict(query_parser.get(
                        'coapplicants', '_get_inactive_associated_coapplicants').format(dealership_id))
                    if not _inactive_coapplicant:
                        _inactive_coapplicant = []
                    return jsonify({"status": "SUCCESS", "data": _active_coapplicant + _inactive_coapplicant})
                return jsonify({"status": "SUCCESS", "data": _active_coapplicant})
            else:
                return _get_result(
                    "SELECT id,dealer_id,pan,aadhar,city FROM t_dealers_coapplicants WHERE is_active = 1")


@app.route('/api/guarantors', methods=['GET'])
@app.route('/api/guarantors/<int:dealership_id>', methods=['GET', 'POST'])
@app.route('/api/guarantors/<int:dealership_id>/<int:id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def _dealership_guarantors(dealership_id=None, id=None):
    if request.method == 'POST':
        data = format_date_in_data(encrypt_data(dict(request.form)), ['dob'])
        data.update({"dealership_id": dealership_id})
        data.update({'last_modified_by': get_jwt_identity()})
        data = _get_id_by_key(data, 'state', 'm_states')
        data = _get_id_by_key(data, 'city', 'm_cities')
        """ 
        Guarantors can be present in more than one dealerships so checking for duplicate KYC is not needed
        """
        # if _check_duplicates("t_dealership_guarantors", data, applicant_id=id):
        #     return jsonify({"status":"ERROR","message":"Duplicate KYC records (Aadhar/PAN/Mobile)"})
        if request.files is not None:
            _status_, result = _upload_kyc_docs(request.files, origin_id=dealership_id, id=id, type='dealers')
            if _status_:
                data.update(result)
            else:
                return jsonify({'status': 'ERROR', 'message': result})
    col_list = mydb._get_columns('t_dealership_guarantors')
    if id:
        if request.method == 'POST':
            query = mydb._gen_update_query('t_dealership_guarantors', col_list, data)
            return _is_rows_affected(query + " WHERE id={}".format(id), True, 15, dealership_id)
        elif request.method == 'GET':
            dealer_details = mydb.run_query(mydb.SELECT,
                                            query_parser.get('guarantors', '_get_guarantor_by_id').format(id))
            return jsonify({'status': 'SUCCESS', 'data': decrypt_data(dealer_details)})
        elif request.method == 'DELETE':
            data = request.get_json()
            mydb.run_query(mydb.UPDATE,
                           mydb._gen_update_query("t_dealership_guarantors", list(data), data) + " WHERE id={0}".format(
                               id))
            return jsonify({"status": "SUCCESS", "message": "User or attachment removed successfully."})

    else:
        if request.method == 'POST':
            query = mydb._gen_insert_query_exclude_cols("t_dealership_guarantors", col_list, data)
            return _is_rows_affected(query, True, 15, dealership_id)
        elif request.method == 'GET':
            if dealership_id:
                _active_guarantors = _get_result_as_dict(
                    query_parser.get('guarantors', '_get_associated_guarantors_by_id').format(dealership_id))
                if _get_user_role(get_jwt_identity()) == 1:
                    """
                    if login user is Admin show active and inactive guarantors, else, show active guarantors only.
                    """
                    if not _active_guarantors:
                        _active_guarantors = []
                    _isactive_guarantors = _get_result_as_dict(
                        query_parser.get('guarantors', '_get_associated_inactive_guarantors_by_id').format(
                            dealership_id))
                    if not _isactive_guarantors:
                        _isactive_guarantors = []
                    return jsonify({'status': 'SUCCESS', 'data': _active_guarantors + _isactive_guarantors})
                return jsonify({'status': 'SUCCESS', 'data': _active_guarantors})
            else:
                return _get_result(query_parser.get('guarantors', '_get_associated_guarantors'))

@app.route('/api/zones', methods=['POST', 'GET'])
@app.route('/api/zones/<id>', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def _zones(id=None):
    if request.method == 'GET':
        _query = query_parser.get('users', '_get_zones')
        if request.args.get('filter'):
            result = _get_result_as_dict(
                query_parser.get('users', '_get_user_zone_info') + " WHERE rm.user_id = {0}".format(get_jwt_identity()))
            if not result:
                result = _get_result_as_dict(_query)
            return jsonify({"status": "SUCCESS", "data": result})
        if id:
            _query += " WHERE id={0}".format(id)
        return _get_result(_query)
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity()})
        if id:
            cols = mydb._get_columns('m_zones')
            query = mydb._gen_update_query('m_zones', cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id={}".format(id))
        else:
            query = mydb._gen_insert_query("m_zones", data)
            return _execute_query(mydb.INSERT, query)
    elif request.method == 'DELETE':
        _query = "DELETE FROM m_zones WHERE id={0}".format(id)
        return _execute_query(mydb.DELETE, _query)


@app.route('/api/states', methods=['GET'])
def _get_states():
    _query = "SELECT id, name from m_states WHERE is_active is TRUE"
    return _get_result(_query)


@app.route('/api/master/external', methods=['GET', 'POST'])
@app.route('/api/master/external/<id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def _extern_api(id=None):
    if request.method == 'GET':
        _query = query_parser.get('external', '_get_external_api')
        if id:
            _query += " WHERE id = {0}".format(id)
        return _get_result(_query)
    if request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity()})
        if data.get('payload'):
            data.update({"payload": json.dumps(data.get('payload'))})
        if data.get('headers'):
            data.update({"headers": json.dumps(data.get('headers'))})
        if id:
            cols = mydb._get_columns('m_external_api')
            query = mydb._gen_update_query('m_external_api', cols, data)
            return _execute_query(mydb.UPDATE, query + "WHERE id = {}".format(id))
        query = mydb._gen_insert_query('m_external_api', data)
        return _execute_query(mydb.INSERT, query)
    if request.method == 'DELETE':
        query = query_parser.get('external', '_remove_external_data')
        return _execute_query(mydb.DELETE, query.format(id))


def _get_vehicle_details(vehicle_no=None):
    if request.method == 'POST':
        if vehicle_no:
            query = query_parser.get('vehicle', '_get_vehicle_data') + " WHERE vehicle_no = '{}'".format(vehicle_no)
            result = mydb.run_query(mydb.SELECT, query)
            if result:
                result[0].update({"details": json.loads(result[0].get('vehicle_details'))})
                return jsonify({"status": "SUCCESS", "data": result[0]})
            else:
                data = {}
                karza_data = {}
                _data = bridge.kyc_check('VEHICLE', {"registrationNumber": vehicle_no}, ENVIRONMENT)
                if not _data:
                    return jsonify({"status": "ERROR", "message": "No data found for the vehicle. "+_support_message})
                _karza_keys = [["vehicleClassDescription", "rc_vh_class_desc"], ["registrationDate", "rc_regn_dt"],
                               ["vehicleCatgory", "rc_vch_catg"], ["registrationNumber", "rc_regn_no"],
                               ["engineNumber", "rc_eng_no"], ["chassisNumber", "rc_chasi_no"],
                               ["numberOfCylinders", "rc_no_cyl"], ["makerDescription", "rc_maker_desc"],
                               ["fuelDescription", "rc_fuel_desc"], ["makerModel", "rc_maker_model"],
                               ["cubicCapacity", "rc_cubic_cap"], ["color", "rc_color"], ["ownerName", "rc_owner_name"],
                               ["insuranceUpto", "rc_insurance_upto"],
                               ["insurancePolicyNumber", "rc_insurance_policy_no"], ["fitnessUpto", "rc_fit_upto"],
                               ["manufacturedMonthYear", "rc_manu_month_yr"], ["insuranceCompany", "rc_insurance_comp"],
                               ["pucNumber", ""], ["pucExpiryDate", ""], ["blackListStatus", ""],
                               ["rcStatus", "rc_status_as_on"], ["rcMobileNo", "rc_mobile_no"], ["blackListInfo", ""]]
                for keys in _karza_keys:
                    karza_data.update({keys[0]: _data.get(keys[0]) or _data.get(keys[1])})
                data.update({"vehicle_no": vehicle_no, "vehicle_details": karza_data,
                             "last_modified_by": get_jwt_identity()})
                cols = mydb._get_columns('t_vehicle_details')
                query = mydb._gen_upsert_query('t_vehicle_details', cols, data)
                _res = mydb.run_query(mydb.INSERT, query)
                if not _res:
                    return jsonify(
                        {"status": "ERROR", "message": "Vehicle details insert/update failed", "data": _data})
                return jsonify({"status": "SUCCESS", "message": "Vehicle details add/update successful", "data": data})
    elif request.method == 'DELETE':
        query = "DELETE FROM t_vehicle_details WHERE vehicle_no = '{}'".format(vehicle_no)
        return _execute_query(mydb.DELETE, query)


@app.route('/api/cibil/<dealership_id>/<id>/<pan>', methods=['GET'])
@jwt_required
def _get_cibil_data(dealership_id, id, pan):
    _cur_date = datetime.date.today()
    _result = mydb.run_query(mydb.SELECT, query_parser.get('external', '_get_cibil_data').format(pan, 1))
    if _result:
        mod_date = _result[0].get("modified_date").date()
        cibil_refresh_interval_days = int(os.getenv('CIBIL_REFRESH_INTERVAL'))
        if _result[0].get("id") and (_cur_date - mod_date).days <= cibil_refresh_interval_days:
            return jsonify({"status": "ERROR",
                            "message": "cibil data can be refreshed only after {no_of_days} days from the last refreshed date  {mod_date}".format(
                                no_of_days=cibil_refresh_interval_days, mod_date=mod_date)})
        else:
            mydb.run_query(mydb.UPDATE, mydb._gen_update_query('t_dealership_applicants_credit_info', ["is_current"], {
                "is_current": 0}) + " WHERE pan = '{0}' and dealership_id = {1}".format(pan, dealership_id))
    _user_type = request.args.get('type')
    data = ''
    if _user_type == 'dealer':
        data = _get_result_as_dict(query_parser.get('dealers', '_get_dealer').format(id))
    elif _user_type == 'coapplicant':
        data = _get_result_as_dict(query_parser.get('coapplicants', '_get_coapplicant_by_id').format(id))
    else:
        data = _get_result_as_dict(query_parser.get('guarantors', '_get_guarantor_by_id').format(id))
    if not data:
        return jsonify({"status": "ERROR", "message": "No applicant found for the provided ID"})
    _data = _get_result_as_dict(query_parser.get('dealership', '_get_dealership_data_cibil').format(dealership_id))
    dob = data[0].get("dob")
    if not dob:
        return jsonify({"status": "ERROR", "message": "DOB is missing. Please update and try again."})
    dob = dob.replace("-", "")
    if _data:
        data[0].update(_data[0])
    data[0].update({"dob": dob})
    result = _cibil._get_data(data[0], ENVIRONMENT, os.getenv('DEALERSHIP_DOCS_BUCKET'))
    if result == "key":
        return jsonify(
            {"status": "ERROR", "message": "Missing mandatory keys.Please check the details of the input PAN"})
    result.update({"dealership_id": dealership_id})
    result.update({"pan": pan})
    if not result.get("id") or not result.get("score"):
        return jsonify({"status": "ERROR", "message": "Enter correct PAN details. Cibil data not found."+_support_message})
    result.update({"cibil_score": result.pop("score")})
    result.update({"document_id": result.pop("id"), "application_id": result.pop("applicationid"), "dealer_id": id})
    _cols = mydb._get_columns('t_dealership_applicants_credit_info')
    affected, row_insert_id = mydb.run_query(mydb.INSERT,
                                             mydb._gen_insert_query_exclude_cols('t_dealership_applicants_credit_info',
                                                                                 _cols, result), row_insert_id=True)
    _html_file = _cibil._get_pdf(result, ENVIRONMENT)
    if not _html_file:
        return jsonify({"status": "ERROR", "message": "Could not download CIBIL PDF report, please try again."})
    _html_file = _html_file.decode()
    _target_file_path = app.config['PROJECT_DIR'] + "/data/document/"
    _html_file_name = "{}_cibil_report.html".format(dealership_id)
    _pdf_name = "{}_cibil_report.pdf".format(dealership_id)
    _file = open(_target_file_path + _html_file_name, "w+")
    _file.write(_html_file)
    _file.close()
    if pdfkit.from_file(os.path.join(_target_file_path, _html_file_name), os.path.join(_target_file_path, _pdf_name),
                        configuration=_wkhtml_config):
        with open(os.path.join(_target_file_path, _pdf_name), 'rb') as new_file:
            _status, _file_url = _s3_file_upload(
                str(dealership_id) + "/{0}/{1}".format(result.get('application_id'), result.get('document_id')),
                _pdf_name,
                dealership_docs_bucket,
                new_file)
        mydb.run_query(mydb.UPDATE,
                       mydb._gen_update_query('t_dealership_applicants_credit_info', ["cibil_file_url"],
                                              {"cibil_file_url": _file_url}) + " WHERE id = {0}".format(row_insert_id))
        os.remove(os.path.join(_target_file_path, _pdf_name))
        os.remove(os.path.join(_target_file_path, _html_file_name))
        result.update({"cibil_file_url": _file_url})
        if result:
            result.pop("userid")
            result.pop("password")
            result.pop("details")
            return jsonify({"status": "SUCCESS", "data": [result]})
    else:
        logger.debug("HTML to PDF conversion error with CIBIL response data.")
        return jsonify({"status": "ERROR", "message": "Report generation failed."+_support_message})


def _get_pan_details(pan_no=None):
    result = mydb.run_query(mydb.SELECT, query_parser.get('authenticate', '_get_pan_details').format(pan_no))
    if result and result[0].get('details'):
        details = json.loads(result[0].get('details'))
        if details.get('status_code') == 101:
            result[0].update({"details": details})
            return jsonify({"status": "SUCCESS", "data": result})
    return _get_karza_data('PAN', {"pan": pan_no}, 't_pan_details',
                           {"pan": pan_no, "last_modified_by": get_jwt_identity()})


@app.route('/api/pan/<pan_no>', methods=['POST', 'DELETE'])
@jwt_required
def _pan_details(pan_no=None):
    if request.method == 'POST':
        if pan_no:
            return _get_pan_details(pan_no=pan_no)
    if request.method == 'DELETE':
        query = "DELETE FROM t_pan_details WHERE pan = '{}'".format(pan_no)
        return _execute_query(mydb.DELETE, query)


@app.route('/api/vkyc/agent/list', methods=['GET'])
@jwt_required
def vkyc_client_agent_id():
    """This API is returns vkyc agent list. This agent id need for Vkyc API [/api/vkyc/<int:dealership_id>/<int:id>/initiation] """
    return jsonify({"data": [{"id": "2c7f0055ee094761baccb3117b914507", "name": "Sowmiya", }],
                    "status": "SUCCESS"})


@app.route('/api/vkyc/<int:dealership_id>/<int:id>/initiation', methods=['POST', 'GET'])
@jwt_required
def vkyc(id=None, dealership_id=None):
    """
    To initiate the virtual kyc for the all applicants via vkyc api
    """
    if request.method == 'GET':
        applicant_type = str(request.args.get("type"))
        _user = mydb.run_query(mydb.SELECT,
                               query_parser.get('vkyc', '_get_customer').format(dealership_id, applicant_type, id))
        if _user:
            return jsonify({"message": "VKYC already initiated", "status": "SUCCESS", "is_initiated": 1})
        return jsonify({"message": "VKYC not initiated", "status": "ERROR", "is_initiated": 0})
    if request.method == "POST":
        data = request.get_json()
        applicant_type = str(data.get('type'))
        if applicant_type:
            # check the applicants type
            if applicant_type == 'dealer':
                _data = mydb.run_query(mydb.SELECT,
                                       query_parser.get('dealers', '_get_all_dealers') + " where id={0}".format(id))
            elif applicant_type == 'guarantor':
                _data = mydb.run_query(mydb.SELECT, query_parser.get('guarantors', '_get_guarantor_by_id').format(id))
            elif applicant_type == 'coapplicant':
                _data = mydb.run_query(mydb.SELECT,
                                       query_parser.get('coapplicants', '_get_coapplicant_by_id').format(id))
        if _data:
            _required_fields = {"agentId": data.get("agent_id"), "applicantpriority": "GENERAL"}
            # generating the payload for vkyc
            for i in ['dealership_id', 'id', 'first_name', 'last_name', 'gender', 'dob', 'mobile', 'address', 'email',
                      'fatherName']:
                if i in ['dob']:
                    _required_fields[i] = str(_data[0].get(i)).lower().replace('-', '/')
                elif i in ['gender']:
                    if _data[0].get(i) in ["male", "M", "Male", "MALE"]:
                        gender = "male"
                    elif _data[0].get(i) in ["female", "F", "Female", "FEMALE"]:
                        gender = "female"
                    else:
                        gender = "other"
                    _required_fields[i] = gender
                elif i == "fatherName":
                    _required_fields[i] = _data[0].get('father_name')
                else:
                    _required_fields[i] = _data[0].get(i)
            payload = json.loads(Template('{"customerId": "$dealership_id","applicationFormData":{"applicationId": "$dealership_id$id","applicationType":  \
            "INDIVIDUAL","applicantType": "APPLICANT","phone": "$mobile","firstName": "$first_name","lastName": "$last_name","fatherName": "$fatherName", \
            "dob": "$dob","email": "$email","gender": "$gender","currentAddress": "$address","permanentAddress": "$address"}, \
            "callAllocation":{"applicantPriority":"$applicantpriority","agentId":"$agentId"}}').substitute(
                **_required_fields),strict=False)
            payload["applicationFormData"]["isCurrentAndPermanentAddressSame"] = False
            # insert vkyc response valuse
            if all(_required_fields.values()):
                response = bridge.kyc_check("VKYC", payload, ENVIRONMENT, mode='basic')
                if response and response.get('status_code') == 101:
                    _details = {"request_id": response.get('request_id'),
                                "transactionId": response['data']['transactionId'], "dealership_id": dealership_id,
                                "applicant_type": str(applicant_type), "applicant_id": id, "status": 1,
                                "created_by": get_jwt_identity()}
                    web_link_payload = {"transaction_id": response['data']['transactionId']}
                    web_response = bridge.kyc_check("VKYC_WEB_LINK", web_link_payload, ENVIRONMENT, mode='basic')
                    query = mydb._gen_insert_query('vkyc_initiation', _details)
                    affected, last_row_id = mydb.run_query(mydb.INSERT, query, row_insert_id=True)
                    if web_response and int(web_response.get("status_code")) == 101:
                        link_expiry_date_in_unix_timestamp = int(web_response.get("data").get("linkExpiryTimestamp"))
                        link_expiry_date = datetime.datetime.utcfromtimestamp(
                            link_expiry_date_in_unix_timestamp).strftime('%Y-%m-%d')
                        web_data = {"web_link": web_response.get("data").get("webLink"),
                                    "web_link_expiry_date": link_expiry_date}
                        query = mydb._gen_update_query('vkyc_initiation', mydb._get_columns("vkyc_initiation"),
                                                       web_data)
                        _execute_query(mydb.UPDATE, query + " WHERE id = {}".format(last_row_id))
                    else:
                        return jsonify({"status": "ERROR",
                                        "message": "VKYC initiation failed."+_support_message})
                    return jsonify({"message": "VKYC initiated successfully", "status": "SUCCESS", "is_initiated": 1})
                else:
                    return jsonify(
                        {"status": "ERROR", "message": "Data insert failed."+_support_message})
            return jsonify({"status": "ERROR", "message": "Mandatory fields are missing"})
        return jsonify({"status": "ERROR", "message": "User not found"})


@app.route('/api/bank/<acc_no>/<ifsc>', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def _get_bank_details(acc_no=None, ifsc=None):
    if request.method == 'GET':
        if acc_no and ifsc:
            return _get_result(query_parser.get('authenticate', '_bank_authentication').format(acc_no, ifsc))
    elif request.method == 'POST':
        response = _get_karza_data('BANK', {"accountNumber": acc_no, "ifsc": ifsc}, 't_bank_details',
                              {"account_no": acc_no, "ifsc": ifsc, "last_modified_by": get_jwt_identity()})
        _push_verified_banks_to_lms(account_no= acc_no)
        return response
    if request.method == 'DELETE':
        query = "DELETE FROM t_bank_details WHERE account_no = '{0}' AND ifsc = '{1}'".format(acc_no, ifsc)
        return _execute_query(mydb.DELETE, query)


@app.route('/api/gst/<gst_no>', methods=['POST', 'DELETE'])
@jwt_required
def _get_gst_details(gst_no=None):
    if request.method == 'POST':
        if gst_no:
            return _get_gst_details(gst_no)
    if request.method == 'DELETE':
        query = "DELETE FROM t_gst_details WHERE gst = '{0}'".format(gst_no)
        return _execute_query(mydb.DELETE, query)


def _get_gst_details(gst_no=None):
    result = mydb.run_query(mydb.SELECT, query_parser.get('authenticate', '_gst_authentication').format(gst_no))
    if result and result[0].get('details'):
        details = json.loads(result[0].get('details'))
        if details.get('status_code') == 101:
            result[0].update({"details": details})
            return jsonify({"status": "SUCCESS", "data": result})
    return _get_karza_data('GST', {"gstin": gst_no, "additionalData": True}, 't_gst_details',
                           {"gst": gst_no, "last_modified_by": get_jwt_identity()})


@app.route('/api/aadhar/<int:aadhar_no>', methods=['POST', 'DELETE'])
@jwt_required
def _aadhar_details(aadhar_no=None):
    if request.method == 'POST':
        data = request.get_json()
        header = request.headers
        if not data.get("name"):
            return jsonify({"status": "SUCCESS", "message": "Please Enter your Name as per your Aadhaar."})
        return _get_aadhar_details(data, aadhar_no, header)
    if request.method == 'DELETE':
        query = query_parser.get('authenticate', '_delete_aadhar_details').format(aadhar_no)
        return _execute_query(mydb.DELETE, query)


def _get_aadhar_details(data, aadhar_no=None, header=None):
    result = mydb.run_query(mydb.SELECT, query_parser.get('authenticate', '_get_aadhar_details').format(aadhar_no))
    if result and result[0].get('details'):
        details = json.loads(result[0].get('details'))
        if details.get('status_code') == "101":
            result[0].update({"details": details})
            return jsonify({"status": "SUCCESS", "data": result})
    consentText = "I authorize Karza Technologies Private Limited to access my Aadhaar number and help me fetch my details. " \
                  "I understand that Karza will not be storing or sharing the same in any manner."
    """ Snippet : str(round((datetime.datetime.now() - datetime.timedelta(seconds=10)).timestamp()))
        Purpose : Current timestamp is changed to a timestamp which was 10 seconds ago and converted to unix timestamp
                  to feed the API. This is done to avoid the timestamp be rejected by the api considering it as 
                  future time since the external api transacts in microseconds.
    """
    return _get_karza_data('AADHAR',
                           {"aadhaarNo": aadhar_no, "name": data.get("name"), "userAgent": header.get("user-Agent"),
                            "ipAddress": header.get("X-Real-Ip"), "consentText": consentText, "consentTime": str(
                               round((datetime.datetime.now() - datetime.timedelta(seconds=10)).timestamp()))},
                           't_aadhar_details', {"aadhar": aadhar_no, "last_modified_by": get_jwt_identity()})


def _get_karza_data(type, payload, table_name, data):
    # TODO Add a Karza error handler based on statusCode. Other than 101, do not update response into details table.
    _data = bridge.kyc_check(type, payload, ENVIRONMENT)
    error_message = "{} details insert/update failed".format(type)
    message = "{} details add/update successful".format(type)
    if not _data:
        return jsonify({"status": "ERROR", "message": "No data found for the {}. {}".format(type, _support_message)})
    _is_verified = 1
    if type in ["AADHAR", "PAN", "GST"]:
        if int(_data.get("status_code")) == 101:
            data.update({"is_verified": _is_verified})
        else:
            logger.info("invalid status code {} ".format(_data.get("status_code")))
            return jsonify({"status": "ERROR", "message": "Details Not Verified"})
    if type == 'BANK':
        _is_verified, message = _clean_karza_bank_response(_data)
        if not _is_verified:
            error_message = "Bank details could not be verified. Please try again."
        data.update({"is_verified": _is_verified})
    data.update({"details": _data})
    cols = mydb._get_columns(table_name)
    query = mydb._gen_upsert_query(table_name, cols, data)
    affected = mydb.run_query(mydb.INSERT, query)
    if not affected or not _is_verified:
        return jsonify({"status": "ERROR", "message": error_message, "data": [data]})
    return jsonify({"status": "SUCCESS", "message": message, "data": [data]})


def _clean_karza_bank_response(result):
    if result:
        try:
            query = query_parser.get('api_key_path', '_get_key_path') + " where api_type='K_pennydrop'"
            keypath_result = mydb.run_query(mydb.SELECT, query)
            key_dict = {}
            input_dict = result
            for keypath in keypath_result:
                key_dict.update({
                    keypath.get("key_name"): dpath.util.get(input_dict, keypath.get("key_path"))
                })
        except Exception as e:
            logger.error('Error while fetch data from karza-> {}'.format(e))
            return 0, "Bank details could not be verified. Please try again."
        status_code = key_dict.get("statusCode")
        bank_response = key_dict.get("bankResponse")
        if status_code and bank_response:
            if status_code.lower() == 'kc01':
                return 1, bank_response
            else:
                logger.error('Error while verifying the bank data from karza: {}-{}'.format(status_code, bank_response))
                return 0, status_code + ':' + bank_response


@app.route('/api/master/city', methods=['GET'])
@app.route('/api/master/city/<int:id>', methods=['GET'])
def get_master_city(id=None):
    if request.method == 'GET':
        _query = query_parser.get('general', '_get_city')
        if id:
            _query += " WHERE id = {0}".format(id)
        return _get_result(_query)


@app.route('/api/master/city', methods=['POST'])
@app.route('/api/master/city/<int:id>', methods=['POST', 'DELETE'])
@jwt_required
def _master_city(id=None):
    if request.method == 'POST':
        data = request.get_json()
        cols = mydb._get_columns('m_cities')
        if id:
            query = mydb._gen_update_query('m_cities', cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id={}".format(id))
        else:
            query = mydb._gen_insert_query('m_cities', data)
            return _execute_query(mydb.INSERT, query)
    elif request.method == 'DELETE':
        return _execute_query(mydb.DELETE, query_parser.get('general', '_delete_city').format(id))


@app.route('/api/pincode/<int:pincode>', methods=['GET'])
def state_pincode(pincode=None):
    if pincode:
        result = mydb.run_query(mydb.SELECT, query_parser.get('general', '_get_state_city_by_pincode').format(pincode))
        if not result:
            return jsonify({"status": "ERROR", "message": "Invalid pincode"})
        return jsonify({"status": "SUCCESS", "data": result})


@app.route('/api/master/states', methods=['GET'])
@app.route('/api/master/states/<int:id>', methods=['GET'])
def master_state(id=None):
    if request.method == 'GET':
        _query = "SELECT id,name,gst_code,is_active FROM m_states"
        if id:
            _query += " WHERE id={0}".format(id)
        return _get_result(_query)


@app.route('/api/master/states', methods=['POST'])
@app.route('/api/master/states/<int:id>', methods=['POST', 'DELETE'])
@jwt_required
def _update_states(id=None):
    if request.method == 'POST':
        data = request.get_json()
        if id:
            cols = mydb._get_columns('m_states')
            query = mydb._gen_update_query('m_states', cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id={}".format(id))
        else:
            query = mydb._gen_insert_query("m_states", data)
            return _execute_query(mydb.INSERT, query)
    elif request.method == 'DELETE':
        _query = "DELETE FROM m_states WHERE id='{}'".format(id)
        return _execute_query(mydb.DELETE, _query)


@app.route('/api/email/groups', methods=['POST', 'GET'])
@app.route('/api/email/groups/<int:group_id>', methods=['POST', 'GET'])
@jwt_required
def _emailing_groups(group_id=None):
    if request.method == 'GET':
        _query = query_parser.get('general', '_get_email_group')
        if group_id:
            _query += " WHERE group_id={0}".format(group_id)
        return _get_result_as_json(_query,['email_list'])
    if request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by":get_jwt_identity()})
        col = mydb._get_columns('t_email_group')
        if group_id:
            query = mydb._gen_update_query('t_email_group', col, data)
            query += f' WHERE group_id={group_id}'
            return _execute_query(mydb.UPDATE, query)
        query = mydb._gen_insert_query('t_email_group', data)
        return _execute_query(mydb.INSERT, query)


@app.route('/api/regions', methods=['GET'])
@app.route('/api/master/regions/<int:id>', methods=['GET'])
def master_region(id=None):
    if request.method == 'GET':
        _query = query_parser.get('general', '_get_region')
        if id:
            _query += " WHERE id={0}".format(id)
        return _get_result(_query)


@app.route('/api/regions', methods=['POST'])
@app.route('/api/master/regions/<int:id>', methods=['POST', 'DELETE'])
@jwt_required
def _update_regions(id=None):
    if request.method == 'POST':
        data = request.get_json()
        if id:
            col = mydb._get_columns('m_regions')
            query = mydb._gen_update_query('m_regions', col, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id={0}".format(id))
        else:
            zone_data = _get_result_as_dict(
                query_parser.get('users', '_get_state_zone_map').format(data.get('state_id')))
            data.update({'zone_id': zone_data[0].get('zone')})
            query = mydb._gen_insert_query("m_regions", data)
            result = _execute_query(mydb.INSERT, query)
            data.update({"regions": [result.get_json().get('row_id')]})
            map_new_region_to_admin(data)
            return result
    elif request.method == 'DELETE':
        _query = "DELETE FROM m_regions WHERE id='{0}'".format(id)
        return _execute_query(mydb.DELETE, _query)


def map_new_region_to_admin(data=None):
    user_ids_as_list_of_dict = _get_result_as_dict(
        query_parser.get('users', '_get_user_details_by_role').format(ADMIN_ROLE_ID))
    user_ids_as_list = [user_id.get('id') for user_id in user_ids_as_list_of_dict]
    for user_id in user_ids_as_list:
        _map_region(user_id, data)


@app.route('/api/regions/los', methods=['GET'])
@jwt_required
def los_regions():
    _query = query_parser.get('users', '_get_user_region').format(get_jwt_identity())
    region = mydb.run_query(mydb.SELECT, _query)
    if not region and not request.args.get('zone'):
        _query = query_parser.get('general', '_get_region')
        return _get_result(_query)
    if request.args.get('zone'):
        if not region:
            _query = query_parser.get('general', '_get_region') + " WHERE rg.zone_id in {}".format(
                _split(request.args.get('zone')))
        else:
            _query += " AND rg.zone_id in {}".format(_split(request.args.get('zone')))
    return _get_result(_query)


@app.route('/api/products/los', methods=["GET"])
@jwt_required
def los_products():
    product = _get_result_as_dict(query_parser.get('users', '_get_user_product').format(get_jwt_identity()))
    if not product:
        _query = query_parser.get('business', '_get_active_loan_products')
        return _get_result(_query)
    return jsonify({'status': 'SUCCESS', 'data': product})


@app.route('/api/omcs', methods=['GET', 'POST'])
@app.route('/api/omcs/<int:id>', methods=['GET', 'POST', 'DELETE'])
def omcs(id=None):
    if request.method == 'GET':
        if id:
            return _get_result(query_parser.get('general', '_get_omcs') + " WHERE id={0}".format(id))
        else:
            return _get_result(query_parser.get('general', '_get_omcs'))
    elif request.method == 'POST':
        data = request.get_json()
        if id:
            col = mydb._get_columns('m_omcs')
            query = mydb._gen_update_query('m_omcs', col, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id='{0}'".format(id))
        else:
            return _is_rows_affected(query_parser.get('general', '_post_omcs').format(data.get('name').upper()))
    if request.method == 'DELETE':
        _query = "DELETE FROM m_omcs WHERE id='{0}'".format(id)
        return _execute_query(mydb.DELETE, _query)


@app.route('/api/business/banks', methods=['GET', 'POST'])
@app.route('/api/business/banks/<int:id>', methods=['GET', 'POST', 'DELETE'])
def _get_business_bank_details(id=None):
    if request.method == 'GET':
        if id:
            return _get_result(
                query_parser.get('business_banks', '_get_business_banks_by_id') + " WHERE id={0}".format(id))
        else:
            return _get_result(query_parser.get('business_banks', '_get_business_banks') + " WHERE is_active is TRUE")
    elif request.method == 'POST':
        data = request.get_json()
        if id:
            col = mydb._get_columns('m_business_banking_details')
            query = mydb._gen_update_query("m_business_banking_details", col, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id='{0}'".format(id))
        else:
            query = mydb._gen_insert_query('m_business_banking_details', data)
            return _is_rows_affected(query)
    if request.method == 'DELETE':
        _query = "DELETE FROM m_business_banking_details WHERE id='{0}'".format(id)
        return _execute_query(mydb.DELETE, _query)


@app.route('/api/banks', methods=['GET', 'POST'])
@app.route('/api/banks/<int:id>', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def banks(id=None):
    if request.method == 'GET':
        if id:
            return _get_result(query_parser.get('general', '_get_banks') + " WHERE id={0}".format(id))
        else:
            return _get_result(query_parser.get('general', '_get_banks'))
    elif request.method == 'POST':
        data = request.get_json()
        if id:
            col = mydb._get_columns('m_banks')
            query = mydb._gen_update_query('m_banks', col, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id='{0}'".format(id))
        else:
            return _is_rows_affected(query_parser.get('general', '_post_banks').format(data.get('name')))
    if request.method == 'DELETE':
        _query = "DELETE FROM m_banks WHERE id='{0}'".format(id)
        return _execute_query(mydb.DELETE, _query)


@app.route('/api/dealership/<int:dealership_id>/outlet', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def _outlet_details(dealership_id=None):
    if request.method == 'GET':
        return _get_result(
            query_parser.get("outlet", "_get_all_outlet_data") + " WHERE dealership_id={}".format(dealership_id))
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity(), "dealership_id": dealership_id})
        cols = mydb._get_columns("outlet_details")
        query = mydb._gen_upsert_query("outlet_details", cols, data)
        return _execute_query(mydb.UPDATE, query)
    elif request.method == 'DELETE':
        return _execute_query(mydb.DELETE, query_parser.get('outlet', '_remove_outlet_details').format(dealership_id))


@app.route('/api/asset', methods=['POST', 'GET'])
@app.route('/api/asset/<asset_id>', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def _asset_details(asset_id=None):
    if request.method == 'GET':
        query = query_parser.get("asset", "_get_all_asset_data")
        if asset_id:
            query += " WHERE asset_id={}".format(asset_id)
        return _get_result(query)
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity()})
        if data.get('details'):
            data.update({"details": json.dumps(data.get('details'))})
        if asset_id:
            cols = mydb._get_columns('m_assets')
            query = mydb._gen_update_query('m_assets', cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE asset_id={}".format(asset_id))
        else:
            query = mydb._gen_insert_query('m_assets', data)
        return _execute_query(mydb.INSERT, query)
    elif request.method == 'DELETE':
        return _execute_query(mydb.DELETE, query_parser.get('asset', '_remove_asset_details').format(asset_id))


@app.route('/api/collection/remarks/options', methods=['POST', 'GET'])
@app.route('/api/collection/remarks/options/<option_id>', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def _collection_options(option_id=None):
    if request.method == 'GET':
        query = query_parser.get('remarks', '_get_collection_remarks_options')
        if option_id:
            return _get_result(query + " WHERE id={}".format(option_id))
        return _get_result(query)
    if request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity()})
        if data.get("key_name"):
            data.update({"key_name": data.get('key_name').lower().replace(' ', '_')})
        cols = mydb._get_columns('m_collection_options')
        if option_id:
            query = mydb._gen_update_query('m_collection_options', cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id = {}".format(option_id))
        query = mydb._gen_insert_query('m_collection_options', data)
        return _execute_query(mydb.INSERT, query)
    if request.method == 'DELETE':
        query = query_parser.get('remarks', '_delete_collection_remarks_options')
        return _execute_query(mydb.DELETE, query.format(option_id))


@app.route('/api/collection/remarks', methods=['POST', 'GET'])
@app.route('/api/collection/remarks/<remark_id>', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def _collection_remarks(remark_id=None):
    if request.method == 'GET':
        query = query_parser.get("remarks", "_get_collection_remarks")
        if remark_id:
            query += " WHERE id={}".format(remark_id)
        return _get_result(query)
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity()})
        if remark_id:
            cols = mydb._get_columns('m_collection_remarks')
            query = mydb._gen_update_query('m_collection_remarks', cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id={}".format(remark_id))
        else:
            query = mydb._gen_insert_query('m_collection_remarks', data)
        return _execute_query(mydb.INSERT, query)
    elif request.method == 'DELETE':
        return _execute_query(mydb.DELETE,
                              query_parser.get('remarks', '_remove_collection_remarks_details').format(remark_id))


@app.route('/api/dealership/<int:dealership_id>/infrastructure', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def _infrastructure_details(dealership_id=None):
    if request.method == 'GET':
        return _get_result(
            query_parser.get("infrastructure", "_get_all_infrastructure_data") + " WHERE dealership_id={}".format(
                dealership_id))
    elif request.method == 'POST':
        data = request.get_json()
        if dealership_id:
            data.update({"last_modified_by": get_jwt_identity(), "dealership_id": dealership_id})
            cols = mydb._get_columns("infrastructure_details")
            query = mydb._gen_upsert_query("infrastructure_details", cols, data)
            return _execute_query(mydb.UPDATE, query)
    elif request.method == 'DELETE':
        return _execute_query(mydb.DELETE, query_parser.get('infrastructure', '_remove_infrastructure_details').format(
            dealership_id))


@app.route('/api/dealership/<int:dealership_id>/references', methods=['POST', 'GET'])
@app.route('/api/dealership/<int:dealership_id>/references/<int:id>', methods=['DELETE'])
@jwt_required
def _dealership_references(dealership_id=None, id=None):
    if request.method == 'GET':
        return _get_result(
            query_parser.get("references", "_get_references") + " WHERE dealership_id={}".format(dealership_id))
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity(), "dealership_id": dealership_id})
        cols = mydb._get_columns("t_dealership_references")
        query = mydb._gen_upsert_query("t_dealership_references", cols, data)
        return _execute_query(mydb.UPDATE, query)
    elif request.method == 'DELETE':
        if id:
            return _execute_query(mydb.DELETE, query_parser.get('references', '_remove_references').format(id))


@app.route('/api/dealership/<int:dealership_id>/details', methods=['POST', 'GET'])
@app.route('/api/dealership/<int:dealership_id>/details/<int:id>', methods=['POST', 'DELETE'])
@jwt_required
def _dealership_other_details(dealership_id=None, id=None):
    if request.method == 'GET':
        return _get_result(
            query_parser.get("details", "_get_other_details") + " WHERE dealership_id={}".format(dealership_id))
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity(), "dealership_id": dealership_id})
        if id:
            cols = mydb._get_columns("t_dealership_other_details")
            query = mydb._gen_update_query("t_dealership_other_details", cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE id={}".format(id))
        query = mydb._gen_insert_query("t_dealership_other_details", data)
        return _execute_query(mydb.INSERT, query)
    elif request.method == 'DELETE':
        if id:
            return _execute_query(mydb.DELETE, query_parser.get('details', '_remove_other_details').format(id))


@app.route('/api/dealership/<int:dealership_id>/tanker/<vehicle_no>', methods=['GET', 'DELETE'])
@app.route('/api/dealership/<int:dealership_id>/tanker', methods=['POST', 'GET'])
@app.route('/api/dealership/tanker', methods=['GET'])
@jwt_required
def _tanker_details(dealership_id=None, vehicle_no=None):
    if request.method == 'GET':
        if dealership_id and vehicle_no:
            return _get_result(query_parser.get("tanker", "_get_all_tanker_data")
                               + "WHERE dealership_id={0} and vehicle_no='{1}'"
                               .format(dealership_id, vehicle_no))
        elif dealership_id:
            return _get_result(
                query_parser.get("tanker", "_get_all_tanker_data") + " WHERE dealership_id={}".format(dealership_id))
        else:
            return _get_result(query_parser.get("tanker", "_get_all_tanker_data"))
    elif request.method == 'POST':
        data = request.get_json()
        if data.get('vehicle_no') and data.get('tanker_type') and data.get('tanker_capacity') and data.get(
                'operation_hours'):
            if data.get('vehicle_no'):
                data.update({"last_modified_by": get_jwt_identity(), "dealership_id": dealership_id})
                cols = mydb._get_columns("tanker_details")
                query = mydb._gen_upsert_query("tanker_details", cols, data)
                return _execute_query(mydb.UPDATE, query)
            else:
                return jsonify({"status": "ERROR", "message": "Invalid vehicle number."})
        else:
            return jsonify({"status": "ERROR", "message": "Missing required data."})
    elif request.method == 'DELETE':
        return _execute_query(mydb.DELETE,
                              query_parser.get('tanker', '_remove_tanker_details').format(vehicle_no, dealership_id))


@app.route('/api/dealership/<int:dealership_id>/bank/loans', methods=['POST', 'GET'])
@app.route('/api/dealership/<int:dealership_id>/bank/loans/<loan_id>', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def bank_loans(dealership_id=None, loan_id=None):
    if request.method == 'GET':
        if dealership_id and loan_id:
            return _get_result(
                query_parser.get('loans_ext', 'get_loans_by_dealership_id') + " WHERE loan_id={1}".format(dealership_id,
                                                                                                          loan_id))
        if dealership_id:
            return _get_result(query_parser.get('loans_ext', 'get_loans_by_dealership_id').format(dealership_id))
    if request.method == 'POST':
        data = request.get_json()
        data.update({"dealership_id": dealership_id, "last_modified_by": get_jwt_identity()})
        if dealership_id and loan_id:
            cols = mydb._get_columns("t_dealership_ext_loans")
            query = mydb._gen_update_query("t_dealership_ext_loans", cols, data)
            return _execute_query(mydb.UPDATE,
                                  query + " WHERE dealership_id={0} and loan_id={1}".format(dealership_id, loan_id))
        if dealership_id:
            query = mydb._gen_insert_query('t_dealership_ext_loans', data)
            return _execute_query(mydb.INSERT, query)
    if request.method == 'DELETE':
        return _execute_query(mydb.DELETE, query_parser.get('loans_ext', '_remove_loan_details').format(loan_id))


@app.route('/api/regions/<int:state_id>', methods=['GET'])
@app.route('/api/states/regions/<int:state_id>', methods=['GET'])
def _get_regions_by_state(state_id=None):
    _query = "SELECT id, name from m_regions where state_id={}".format(state_id)
    return _get_result(_query)


@app.route('/api/regions/all', methods=['GET'])
def _get_all_regions():
    _query = "SELECT RTRIM(name) as name,id as region from m_regions"
    return _get_result(_query)


@app.route('/api/user/<int:user_id>/map/region', methods=['POST', 'DELETE', 'GET'])
def _map_region_by_id(user_id=None):
    if request.method == 'GET':
        return jsonify({'status': 'SUCCESS', 'data': _get_user_regions(user_id)})
    else:
        return _map_region(user_id)


@app.route('/api/user/map/region', methods=['POST', 'DELETE'])
@jwt_required
def _map_region(_user_id=None, data=None):
    if _user_id is None:
        _user_id = get_jwt_identity()
    if not data:
        data = request.get_json()
    _region_data = data.get('regions')
    if request.method == 'POST':
        _query = "INSERT into t_users_region_map(user_id,region_id) values (%s, %s)"
        _insert_region_data = []
        for _region in _region_data:
            _value = (_user_id, _region)
            _insert_region_data.append(_value)
        _status, _error = mydb._bulk_insert(_query, _insert_region_data)
        _success_msg = {"status": "SUCCESS", "message": "Regions updated for the user."}
        _error_msg = {"status": "ERROR", "message": "Could not map the regions. "+_support_message}
        return jsonify(_success_msg) if _status else jsonify(_error_msg)

    elif request.method == 'DELETE':
        _query = "DELETE FROM t_users_region_map WHERE user_id = {0} AND region_id IN {1}" \
            .format(_user_id, tuple(_region_data) if (len(_region_data) > 1) else "(" + str(_region_data[0]) + ")")
        _result = mydb.run_query(mydb.DELETE, _query)
        if _result > 0:
            return jsonify(
                {"status": "SUCCESS", "message": "Regions has been unmapped successfully.", "result": _result})
        else:
            return jsonify(
                {"status": "ERROR", "message": "Requested regions were not found mapped to the user",
                 "result": _result})


@app.route('/api/role/<int:role_id>/map/product', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def _map_product_by_role_id(role_id=None):
    if role_id:
        if request.method == 'GET':
            return jsonify({'status': 'SUCCESS', 'data': _get_products_by_role_id(role_id)})
        else:
            data = request.get_json()
            _product_data = data.get('products')
            if request.method == 'POST':
                _query = "INSERT into t_role_product_map(role_id,product_id) values (%s, %s)"
                _insert_product_data = []
                for _product in _product_data:
                    _value = (role_id, _product)
                    _insert_product_data.append(_value)
                _status, _error = mydb._bulk_insert(_query, _insert_product_data)
                _success_msg = {"status": "SUCCESS", "message": "Products updated for the role."}
                _error_msg = {"status": "ERROR", "message": "Could not map the product for the role. "+_support_message}
                return jsonify(_success_msg) if _status else jsonify(_error_msg)
            elif request.method == 'DELETE':
                _query = "DELETE FROM t_role_product_map WHERE role_id = {0} AND product_id IN {1}" \
                    .format(role_id,
                            tuple(_product_data) if (len(_product_data) > 1) else "(" + str(_product_data[0]) + ")")
                _result = mydb.run_query(mydb.DELETE, _query)
                if _result > 0:
                    return jsonify(
                        {"status": "SUCCESS", "message": "Products unmapped successfully.", "result": _result})
                else:
                    return jsonify(
                        {"status": "ERROR", "message": "Requested products were not found mapped to the role",
                         "result": _result})
    else:
        return jsonify({"status": "ERROR", "message": "Value for role_id not sent"})


@app.route('/api/zone/<int:zone_id>/map', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def zone_state_map_by_id(zone_id=None):
    if request.method == 'GET':
        return (
            {"status": "SUCCESS",
             "data": _get_result_as_dict(query_parser.get('map', '_get_zone_states').format(zone_id))})
    data = request.get_json()
    _data = {"zone_id": zone_id}
    state_data = data.get("state_id")
    if request.method == 'POST':
        query = "update m_states set zone_id={0}"
        unmap_states = []
        map_states = []
        for i in state_data:
            _status = _get_result_as_dict(query_parser.get('map', '_get_check_zone_isnull').format(str(i)))
            if _status and _status[0].get('zone_status') == 1:
                unmap_states.append(i)
            else:
                map_states.append(i)
        unmap_states_list = tuple(unmap_states)
        if len(unmap_states) > 0:
            cols = mydb._get_columns("m_states")
            query = mydb._gen_update_query("m_states", cols, _data)
            _execute_query(mydb.UPDATE, query + " WHERE id in ({}) ".format((",".join(map(str, unmap_states_list)))))

        return jsonify({"status": "SUCCESS",
                        "message": "state id {0} already mapped in another zone and state id {1} mapped successful".format(
                            map_states, unmap_states)})
    elif request.method == 'DELETE':
        data = request.get_json()
        state_data = data.get("state_id")
        state_data_list = tuple(state_data)
        query = "update m_states set zone_id=NULL"
        return _execute_query(mydb.UPDATE, query + " WHERE id in ({}) ".format((",".join(map(str, state_data_list)))))


@app.route('/api/states/unmapped', methods=['GET'])
@jwt_required
def unmapped_zones():
    if request.method == 'GET':
        return ({"status": "SUCCESS", "data": _get_result_as_dict(query_parser.get('map', '_get_unmapped_states'))})


@app.route('/api/state/<int:state_id>/map', methods=['GET', 'POST', 'DELETE'])
@jwt_required
def state_region_map_by_id(state_id=None):
    if request.method == 'GET':
        return ({"status": "SUCCESS",
                 "data": _get_result_as_dict(query_parser.get('map', '_get_state_regions').format(state_id))})
    data = request.get_json()
    _data = {"state_id": state_id}
    region_data = data.get("region_id")
    if request.method == 'POST':
        query = "update m_regions set state_id={0}"
        unmap_regions = []
        map_regions = []
        for i in region_data:
            _status = _get_result_as_dict(query_parser.get('map', '_get_check_state_isnull').format(str(i)))
            if _status and _status[0].get('state_status') == 1:
                unmap_regions.append(i)
            else:
                map_regions.append(i)
        unmap_region_list = tuple(unmap_regions)
        if len(unmap_regions) > 0:
            cols = mydb._get_columns("m_regions")
            query = mydb._gen_update_query("m_regions", cols, _data)
            _execute_query(mydb.UPDATE, query + " WHERE id in ({}) ".format((",".join(map(str, unmap_region_list)))))
        return jsonify({"status": "SUCCESS",
                        "message": "state id {0} already mapped in another zone and state id {1} mapped successful".format(
                            map_regions, unmap_regions)})
    elif request.method == 'DELETE':
        data = request.get_json()
        region_data = data.get("region_id")
        region_data_list = tuple(region_data)
        query = "update m_regions set state_id=NULL"
        return _execute_query(mydb.UPDATE, query + " WHERE id in ({}) ".format((",".join(map(str, region_data_list)))))


@app.route('/api/regions/unmapped', methods=['GET'])
@jwt_required
def unmapped_regions():
    if request.method == 'GET':
        return {"status": "SUCCESS", "data": _get_result_as_dict(query_parser.get('map', '_get_unmapped_regions'))}


def _whatsapp_push_reminder(to, data, templateid):
    body = []
    for values in data:
        body.append({'type': 'text', 'text': '*{}*'.format(values)})
    body = {'body': body}
    url = "https://push.aclwhatsapp.com/pull-platform-receiver/wa/messages"
    payload = {
        "messages": [
            {
                "sender": os.getenv('BOT_NUMBER'),
                "to": to,
                "messageId": "hhjyhu776654488536374",
                "channel": "wa",
                "type": "template",
                "template": {
                    "templateId": templateid,
                    "langCode": "en"
                }
            }
        ],
        "responseType": "json"
    }
    payload.get('messages')[0].get('template').update(body)
    header = {'Content-Type': 'application/json', 'user': os.getenv('WHATSAPP_USERNAME'),
              'pass': os.getenv('WHATSAPP_PASSWORD')}
    return req.post(url, json=payload, headers=header).json()


@app.route('/api/loan/report/dealership/<int:dealership_id>', methods=['GET'])
@app.route('/api/loan/report/whatsapp', methods=['POST'])
def _get_loan_due_report(dealership_id=None):
    if dealership_id:
        data = {}
        _sanctioned_loan_amount = mydb.run_query(mydb.SELECT,
                                                 "SELECT amount_disbursed from t_dealership_loans WHERE dealership_id={}".format(
                                                     dealership_id))
        if _sanctioned_loan_amount:
            data.update({"sanctioned_loan_amount": (_sanctioned_loan_amount[0].get('amount_disbursed'), 0)})
        data.update({"cust_details": _lms_data_handler('dealership','customer_details',data = {'dealership_id': dealership_id})})
        data.update({"overdue": _lms_data_handler('dealership', 'loan_overdue', data = {'dealership_id': dealership_id})})
        data.update({"due": _lms_data_handler('dealership', 'loan_due', data = {'dealership_id': dealership_id})})
        return jsonify({'status': 'SUCCESS', 'data': data})
    else:
        logger.info("Generating Whatsapp due overdue report....")
        _due_data = _lms_data_handler('dealership', 'due_report_for_reminder')
        _over_due_data = _lms_data_handler('dealership', 'over_due_report_for_reminder')
        return jsonify(status="SUCCESS", due=_due_data, overdue=_over_due_data)


def _email_report(reports):
    msg = {}
    file_buffers = []
    file_names = []
    _cur_date = datetime.date.today()
    msg.update({"subject": "Petromoney loan reports for ( {}-{}-{} ) - Reg.".format(_cur_date.day, _cur_date.month,
                                                                                    _cur_date.year)})
    msg.update({
        "body": "Hi Team,\nGreetings from Petromoney!\nPlease find attached Loan reports (Due/Overdue) "
                "of {}-{}-{} for your perusal.\nFor any discrepancies, " + _support_message + ".\nThanks\nPetromoney IT"
            .format(_cur_date.day, _cur_date.month, _cur_date.year)})
    msg.update({"recipients": report_recipients})
    for report_key in reports.keys():
        df = pd.DataFrame(reports[report_key])
        file_names.append(report_key + '.csv')
        file_buffer = io.StringIO()
        df.to_csv(file_buffer, index=False)
        file_buffers.append(file_buffer)
    return _send_mail(msg, file_name=file_names, file_type="text/csv", file_buffer=file_buffers)


@app.route('/api/loan/report/<int:_is_report>', methods=['POST'])
@app.route('/api/loan/report', methods=['GET'])
@jwt_required
def _get_loan_report(_is_report=None):
    data = {}
    current_user = get_jwt_identity()
    query = (query_parser.get('users', '_get_user_details') + " AND u.id = {}").format(current_user)
    current_user_details = mydb.run_query(mydb.SELECT, query)
    if request.args.get('region') == 'ALL':
        due_section, due_query_key, due_format_data = 'dealership' , 'all_loan_dues', {}
        overdue_section, overdue_query_key, overdue_format_data = 'dealership' , 'all_loan_overdues', {}
    elif current_user_details[0].get('role_id') == 13:
        return _get_loan_due_report((mydb.run_query(mydb.SELECT,
                                                    query_parser.get('dealers', '_get_dealership_id').format(
                                                        current_user_details[0].get('mobile'))))[0].get(
            'dealership_id'))
    else:
        _user_regions = mydb.run_query(mydb.SELECT,
                                       query_parser.get('users', '_get_user_regions').format(
                                           current_user))
        region_list = ''
        if not _user_regions:
            return jsonify({'status': 'ERROR', 'message': "Regions not mapped to the user. "+_support_message})
        for region in _user_regions:
            region_list += "'{} Retail RO',".format(region.get('region_name'))
        region_list = region_list[:-1]
        due_section, due_query_key, due_format_data = 'dealership' , 'due_report_by_region', {"region_list":region_list}
        overdue_section, overdue_query_key, overdue_format_data = 'dealership' , 'overdue_report_by_region', {"region_list":region_list}
    data.update({"overdue": _lms_data_handler(overdue_section, overdue_query_key, overdue_format_data)})
    data.update({"due": _lms_data_handler(due_section, due_query_key, due_format_data)})
    if _is_report == 1:
        _report_dict = {}
        _report_dict.update({"due_report": data.get('due'), "overdue_report": data.get('overdue')})
        _email_status = _email_report(_report_dict).get_json()
        if _email_status.get('delivery'):
            return jsonify({'status': 'SUCCESS', 'message': _email_status.get('message')})
        else:
            return jsonify({'status': 'ERROR', 'message': _email_status.get('message')})
    return jsonify({'status': 'SUCCESS', 'data': data})


def _append_remarks(bulk_data=None, _is_email=None):
    # todo
    if bulk_data:
        query = query_parser.get('dealership', '_get_all_collection_remarks')
        remarks_data = mydb.run_query(mydb.SELECT, query)
        if not remarks_data:
            return bulk_data
        query = query_parser.get('dealership', '_get_all_dealerships')
        omc_data = mydb.run_query(mydb.SELECT, query)
        query = query_parser.get('remarks', "_get_collection_remarks_options")
        options = mydb.run_query(mydb.SELECT, query)
        if _is_email:
            for r in remarks_data:
                _details = json.loads(r.get('details'))
                for _o in options:
                    for _det in _details:
                        if _det.get('options'):
                            for _d in _det.get('options'):
                                if _o.get('key_name') in list(_d.keys()):
                                    _d.update({'label': _d.get(_o.get('key_name'))})
                                    _d.pop(_o.get('key_name'))
                r.update({"details": json.dumps(_details)})
        if remarks_data and omc_data:
            for data in bulk_data:
                data.update({"remarks": []})
                for remarks in remarks_data:
                    if data.get('prospectcode') == remarks.get("prospect_code"):
                        if remarks.get('details'):
                            remarks_details = json.loads(remarks.get('details').replace("'", '"'))
                            data.update({"remarks": remarks_details})
            for data in bulk_data:
                for omc in omc_data:
                    if omc.get('id') == int(data.get('cust_code')):
                        data.update({"omc": omc.get('omc')})
            if _is_email:
                for data in bulk_data:
                    remarks = data.get('remarks')
                    _remarks = ''
                    if not remarks:
                        data.update({'remarks': ''})
                    if remarks:
                        for _r in remarks:
                            if _r.get('options'):
                                options = ''
                                for _o in _r.get('options'):
                                    options += str(_o.get('label')) + ', '
                                _r.update({"options": options[:-2]})
                            _remarks += str(_r.get("label") + (" - " if str(_r.get('options', '')) else '') + str(
                                _r.get('options', ''))) + " ,"
                    data.update({"remarks": _remarks[:-2]})
            return bulk_data
        return bulk_data
    return bulk_data


def _collection_remarks_map(remarks_data=None):
    prospectcode_list = []
    cust_code_list = []
    for data in remarks_data:
        prospectcode_list.append(data.get('prospect_code'))
    prospectcode_list = str(prospectcode_list).replace("[", "(").replace("]", ")")
    oracle_data = _lms_data_handler('dealership', 'loan_dues_by_prospect_code', data = {'prospectcode_list':prospectcode_list})
    oracle_data.extend(_lms_data_handler('dealership', 'loan_overdues_by_prospect_code', data = {'prospectcode_list':prospectcode_list}))
    for data in oracle_data:
        cust_code_list.append(data.get('cust_code'))
    cust_code_list = str(cust_code_list).replace("[", "(").replace("]", ")")
    query = query_parser.get('dealership', '_get_all_dealerships_with_omc')
    omc_data = mydb.run_query(mydb.SELECT, query + " WHERE md.id IN " + cust_code_list)
    for data in oracle_data:
        for omc in omc_data:
            if int(data.get('cust_code')) == omc.get('cust_code'):
                data.update({"omc": omc.get('omc')})
    return oracle_data


@app.route('/api/loan/collection/remarks', methods=['GET'])
@jwt_required
def _collection():
    _limit=int(request.args.get('limit',50))
    _offset=int(request.args.get('offset',0))*_limit
    remarks_data = mydb.run_query(mydb.SELECT, query_parser.get('dealership', '_get_all_collection_remarks') + f" LIMIT {_offset},{_limit}")
    if not remarks_data:
        return jsonify({"status": "ERROR", "message": "No data found."})
    data = _collection_remarks_map(remarks_data)
    _final_data = []
    data = sorted(data, key=itemgetter("cust_code"))
    for key, value in groupby(data, key=itemgetter("cust_code")):
        _inner_data = {}
        _data = []
        tot_prin_overdue = 0
        tot_int_overdue = 0
        tot_penal_overdue = 0
        tot_disb_amt = 0
        tot_prin_due = 0
        tot_overdue = 0
        tot_due = 0
        for i in value:
            _inner_data.update({"cust_code": i.get('cust_code'), "applicant_name": i.get('applicant_name'),
                                "cust_region": i.get('cust_region'), "omc": i.get('omc')})
            _data.append(
                {"prospectcode": i.get('prospectcode'), "disb_amt": i.get('disb_amt'), "disb_date": i.get('disb_date'),
                 "duedate": i.get('duedate'), "prin_due": i.get('prin_due'), "prin_overdue": i.get('prin_overdue'),
                 "int_overdue": i.get('int_overdue'), "penal_overdue": i.get('penal_overdue'), "dpd": i.get('dpd')})
            if i.get('dpd') or i.get('dpd') == 0:
                tot_overdue += i.get('tot_due', 0)
            else:
                tot_due = tot_due + i.get('tot_due', 0)
            tot_prin_overdue += i.get('prin_overdue', 0)
            tot_int_overdue += i.get('int_overdue', 0)
            tot_penal_overdue += i.get('penal_overdue', 0)
            tot_disb_amt += i.get('disb_amt', 0)
            tot_prin_due += i.get('prin_due', 0)
        _inner_data.update({"tot_prin_overdue": tot_prin_overdue, "tot_int_overdue": tot_int_overdue,
                            "tot_penal_overdue": tot_penal_overdue,
                            "tot_overdue": tot_overdue, "tot_due": tot_due, "tot_disb_amt": tot_disb_amt,
                            "tot_prin_due": tot_prin_due})
        _inner_data.update({"loan_data": _data})
        _final_data.append(_inner_data)
    return jsonify({"status": "SUCCESS", "data": _final_data})


@app.route('/api/business/products', methods=['GET', 'POST'])
@app.route('/api/business/products/<product_id>', methods=['POST', 'GET', 'DELETE'])
@jwt_required
def _loan_products(product_id=None):
    if request.method == 'GET':
        _query = query_parser.get('business', '_get_loan_products')
        return _get_result(_query)
    if request.method == 'POST':
        data = request.get_json()
        data.update({'last_modified_by': get_jwt_identity()})
        if product_id:
            cols = mydb._get_columns('t_loan_products')
            query = mydb._gen_update_query('t_loan_products', cols, data)
            return _execute_query(mydb.UPDATE, query + " WHERE product_id = {}".format(product_id))
        query = mydb._gen_insert_query('t_loan_products', data)
        return _execute_query(mydb.INSERT, query)
    if request.method == 'DELETE':
        query = "DELETE FROM t_loan_products WHERE product_id = {}".format(product_id)
        return _execute_query(mydb.DELETE, query)


@app.route('/api/business/products/valid', methods=['GET'])
@jwt_required
def _loan_products_active():
    if request.method == 'GET':
        _query = query_parser.get('business', '_get_active_loan_products')
        return _get_result(_query)


@app.route('/api/business/loanbook', methods=['GET'])
@jwt_required
def _loan_book():
    return jsonify(
        {"status": "SUCCESS", "data": lms('_get_loan_book')})


def generate_noc_pdf_letter(dealership_id, data, noc_letter_template):
    """
    Generating a noc pdf based on noc type
    :param dealership_id: A unique that identify the dealership
    :param data: required input data to create the pdf
    :param noc_letter_template: noc template configuration
    :return: upload pdf url :if success otherwise return the error message
    """
    _cur_date = datetime.date.today()
    if data:
        data[0].update({"date": "{}-{}-{}".format(_cur_date.day, _cur_date.month, _cur_date.year)})
        data[0].update({'amount': str(data[0].get("amount")) + "(" + num2words(
            decimal.Decimal(data[0].get("amount"))) + " Rupees Only)"})
        data = data[0]
        _target_file_path = app.config['TARGET_FILE_PATH'] + "/{}/".format(str(dealership_id))
        _file_name = "{}_noc_letter.html".format(dealership_id)
        _pdf_name = "{}_noc_letter.pdf".format(dealership_id)
        _noc_letter = _find_and_replace(noc_letter_template, _target_file_path, _file_name, data)
        options.update({'header-html': 'template/header.html'})
        with open(_noc_letter) as fin:
            logger.debug("Generating noc letter...")
            pdfkit.from_file(fin, os.path.join(_target_file_path, "noc_letter.pdf"), options=options,
                             configuration=_wkhtml_config)
        message_bytes = open(os.path.join(_target_file_path, "noc_letter.pdf"), "rb").read()
        file_bytes = base64.b64encode(message_bytes)
        file_message = file_bytes.decode('ascii')
        _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(
            "{}/{}".format(str(dealership_id), "noc"), _pdf_name,
            dealership_docs_bucket, file_message)
        if _upload_status:
            return {"status": "SUCCESS", "message": "NOC letter generated and approved", "file": _uploaded_file_url}
        return {'status': 'ERROR', 'message': 'Unable to Download data'}
    else:
        return {"status": "ERROR",
                "message": "Sanction letter could not be generated."+_support_message}


def get_noc_type(dealership_id):
    """
    This function to getting the noc type based on dealership id
    :param dealership_id: A unique that identify the dealership
    :return: noc type ex:"NOC CLOSED"
    """
    query = query_parser.get('dealership', '_get_applicant_code').format(dealership_id)
    applicant_code = mydb.run_query(mydb.SELECT, query)
    if applicant_code:
        applicant_code = applicant_code[0].get('applicant_code')
    else:
        return jsonify({"status": "ERROR",
                        "message": "Applicant code is unavailable for provided dealership id."+_support_message})
    # fetching th a lms data using applicant code
    lms_data = _lms_data_handler('noc','loan_book_by_applicant_code',data = {'applicant_code':applicant_code})
    if lms_data:
        if lms_data[0].get("dpd") == 0:
            noc_type = "NOC OPEN REGULAR"
        elif lms_data[0].get("dpd") > 0:
            noc_type = "NOC OPEN OVERDUE"
    else:
        noc_type = "NOC CLOSED"
    return noc_type


def validate_and_change_noc_status(dealership_id, update_data):
    """
    This function validates the current status and the request status and the change to status.
    :param dealership_id: A unique that identify the dealership
    :param update_data: Update data
    :return: change the status of the noc
    """
    logger.info("Update the noc letter status")
    data = mydb.run_query(mydb.SELECT, query_parser.get('noc', '_get_nocs').format(f'dealership_id={dealership_id}'))
    if data:
        current_status = data[0].get("status")
        requested_status = update_data.get("status")
        if current_status == "submitted" and requested_status in ["approved", "rejected"]:
            cols = mydb._get_columns("noc_letter")
            query = mydb._gen_update_query('noc_letter', cols, update_data)
            _execute_query(mydb.UPDATE, query + " where dealership_id ={}".format(dealership_id))
            return jsonify({"message": f'NOC letter {requested_status} successfully.', "status": "SUCCESS", "data": []})
        return jsonify(status="ERROR",
                       message=f"Couldn't change the NOC status.Because NOC status is {current_status}")
    return jsonify(status="ERROR", message=f"Couldn't change the NOC status.Because No records found")


@app.route('/api/dealership/noc', methods=['GET'])
@jwt_required
def getting_noc_letters_details():
    """
    This api return noc details
    """
    data = mydb.run_query(mydb.SELECT, query_parser.get('noc', '_get_all_noc_details'))
    if data and data[0].get("dealership_id"):
        return jsonify({"message": "successful transaction", "status": "SUCCESS", "data": data})
    return jsonify({"message": "No noc found", "status": "SUCCESS", "data": []})


@app.route('/api/dealership/<int:dealership_id>/noc/submit', methods=['POST'])
@jwt_required
def submit_noc_letter(dealership_id):
    """
    This to submit the noc letter
    """
    data = mydb.run_query(mydb.SELECT, query_parser.get('noc', '_get_nocs').format(f'dealership_id={dealership_id}'))
    if data:
        return jsonify(status="ERROR", message="NOC letter is already submitted.")
    noc_type = get_noc_type(dealership_id)
    if noc_type:
        _cur_date = datetime.date.today()
        return _execute_query(mydb.INSERT, mydb._gen_insert_query('noc_letter',
                                                                  {"dealership_id": dealership_id, "noc_type": noc_type,
                                                                   "created_by": get_jwt_identity(),
                                                                   'created_date': _cur_date,
                                                                   'modified_date': _cur_date,
                                                                   'modified_by': get_jwt_identity(),
                                                                   "status": "submitted"}),
                              success_message=f'NOC letter Submitted successfully.')
    return jsonify(status="ERROR", message=f"Couldn't Submit NOC.")


@app.route('/api/dealership/<int:dealership_id>/noc/reject', methods=['POST'])
@jwt_required
def send_for_approval_noc_letter(dealership_id):
    """
    This to reject the noc letter
    """
    if _get_user_role(get_jwt_identity()) == 1:
        request_data = request.get_json()
        noc_type = get_noc_type(dealership_id)
        update_date = {"noc_type": noc_type, "status": "rejected", "noc_letter_url": "",
                       "remarks": request_data.get("remarks")}
        return validate_and_change_noc_status(dealership_id, update_date)
    return jsonify(status="ERROR", message="Couldn't process your request,Only Admin can approve the NOC.")


@app.route('/api/dealership/<int:dealership_id>/noc/approve', methods=['POST'])
@jwt_required
def send_for_approved_noc_letter(dealership_id):
    """
    This to approved the noc letter
    """
    if _get_user_role(get_jwt_identity()) == 1:
        request_data = request.get_json()
        noc_type = get_noc_type(dealership_id)
        try:
            if noc_type:
                pdf_details = mydb.run_query(mydb.SELECT,
                                             query_parser.get('noc', '_get_closed_loan_details').format(
                                                 dealership_id))
                if noc_type == "NOC CLOSED":
                    pdf_status = generate_noc_pdf_letter(dealership_id, pdf_details,
                                                         app.config['NOC_CLOSED_LETTER_TEMPLATE'])
                elif noc_type in ["NOC OPEN REGULAR", "NOC OPEN OVERDUE"]:
                    pdf_status = generate_noc_pdf_letter(dealership_id, pdf_details,
                                                         app.config['NOC_OPEN_LETTER_TEMPLATE'])
                else:
                    return jsonify(status="ERROR", message="No noc found")
                if pdf_status.get("status") == "SUCCESS":
                    update_date = {"noc_type": noc_type, "status": "approved", "noc_letter_url": pdf_status.get("file"),
                                   "remarks": request_data.get("remarks") if request_data.get("remarks") else ""}
                    return validate_and_change_noc_status(dealership_id, update_date)
                return jsonify(pdf_status)
        except:
            return jsonify(status="ERROR", message="Unable to process the request. "+_support_message)
    return jsonify(status="ERROR", message="Couldn't process your request,Only Admin can approve the NOC.")


@app.route("/api/data-migration/los-to-lms", methods=['POST'])
@jwt_required
def lms_to_los_data_migration():
    request_data = request.get_json()
    if request_data and list(request_data.keys())[0] in ["entity_name", "table_name"]:
        entity_details = mydb.run_query(mydb.SELECT, query_parser.get('migration',
                                                                      '_get_migration_info') + f" where {list(request_data.keys())[0]} in {str(request_data.get(list(request_data.keys())[0])).replace('[', '(').replace(']', ')')}")
        [entity.update({"primary_fields": json.loads(entity.get("primary_fields"))}) for entity in entity_details]
        if entity_details:
            for entity_value in [entity.values() for entity in entity_details]:
                entity_name, proc_name, table, fields = entity_value
                if proc_name:
                    _execute_query("proc", proc_name, success_message=f"{entity_name} Loaded Successfully")
                tar_data = lms_db.run_query(lms_db.SELECT, f"SELECT {','.join(fields)} FROM `{table}`")
                conditions = ""
                empty_conditions = "('')"
                for fields_name in fields:
                    migrated_data = tuple([d.get(fields_name) for d in tar_data])
                    conditions += f"cast({fields_name} as varchar(1000)) not in {migrated_data if migrated_data else empty_conditions} and "
                src_data = mydb.run_query(mydb.SELECT, f"SELECT * FROM `{table}` where {conditions[:-5]}")
                if src_data:
                    try:
                        src_df = pd.DataFrame.from_dict(src_data)
                        if not entity_name == "customers":
                            src_df.drop(['id'], axis=1, inplace=True)
                        logger.info("Inserting data from staging tables in LOS to LMS")
                        src_df.to_sql(table, con=engine, index=False, if_exists='append')
                    except Exception as e:
                        logger.error('Error while moving data from los-> {}'.format(e))
                        return jsonify(status="ERROR", message=f"Something went wrong. '{table}' did not get loaded")
            return jsonify(status="SUCCESS",
                           message=f"{','.join([entity.get('table_name') for entity in entity_details])} loaded successfully")
    return jsonify(status="ERROR", message=f"Please validate your request")


def _get_loan_stats(args=None, user_id=None, search=0):
    _status = args.get("status")
    product = args.get('product')
    from_date = args.get("from")
    to_date = args.get("to")
    page, rc = 0, 0
    if product:
        product = _split(product)
    else:
        if _get_user_role(get_jwt_identity()) == 5:
            user_product = mydb.run_query(mydb.SELECT,
                                          query_parser.get('users', '_get_user_product').format(get_jwt_identity()))
            products = []
            for product in user_product:
                products.append(product.get("product_id"))
            product = ("(" + ",".join(map(str, products)) + ")")
    if from_date and from_date == to_date:
        to_date = _increment_date(to_date)
    query = query_parser.get('dealership', '_get_all_loans')
    sanc_query = ''
    if _status:
        status = _split(_status)
        _status = _status.split(',')
        query += " AND tdl.status in {}".format(status)
        _join = ''
        date_cols = {"pre_submit": "tdl.created_date", "submitted": "tdl.modified_date",
                     "loan_approval": "tdl.modified_date",
                     "loan_review": "tdl.modified_date", "approved": "tdl.loan_approved_rejected_date",
                     "disbursement_approval": "tdl.loan_approved_rejected_date",
                     "disbursement_approved": "tdl.loan_disbursement_approved_rejected_date",
                     "disbursed": "tdl.loan_disbursed_date", "rejected": "tdl.loan_approved_rejected_date"}
        for i in _status:
            if i == 'disbursed':
                sanc_query, join = _disbursed_details(date_col=date_cols.get(i), _from=from_date, _to=to_date,
                                                      product=product)
                _join += join
            else:
                if from_date:
                    _join += " CAST({0} as date) BETWEEN '{1}' AND '{2}' AND".format(date_cols.get(i), from_date,
                                                                                     to_date)
                else:
                    _join += " CAST({0} as date) AND".format(date_cols.get(i))
            if _join:
                query = query + " AND " + _join[:-3]
    query += _region_filter(args, user_id, search)
    if product:
        query += " AND lp.product_id in {}".format(product)
    if search:
        query += " AND CONCAT(tdl.dealership_id,'-',md.name) LIKE '%{}%'".format(args.get('key'))
        return query
    query += " ORDER BY tdl.modified_date DESC"
    if args.get('pagination') == '1':
        row_count = int(args.get('row_count', 15))
        page = int(args.get('page', 0)) * row_count
        res = mydb.run_query(mydb.SELECT, query)
        if res:
            rc = len(res)
        query += " LIMIT {0},{1}".format(page, row_count)
        page = page // row_count
    if _status and sanc_query:
        for i in _status:
            if i == 'disbursed':
                query = "SELECT * FROM (" + query + ") m LEFT JOIN (" + sanc_query + ") t ON m.id=t.loan_id "
    return query, page, rc


def _increment_date(to_date):
    return (datetime.datetime.strptime(to_date, "%Y-%m-%d") + datetime.timedelta(days=1)).date()


def _region_filter(args, user_id, search):
    r_join = ''
    if not args.get('zone') and not args.get('region') and not search:
        _query = query_parser.get('users', '_get_user_region_id').format(user_id)
        region = _get_result_as_dict(_query)
        if not region[0].get('region_id'):
            _query = query_parser.get('users', '_get_zone_region_map_concat')
            region = _get_result_as_dict(_query)
        r_join = " AND md.region in {}".format(_split(region[0].get('region_id')))
    if args.get('zone'):
        zone_region = _get_result_as_dict(
            query_parser.get('users', '_get_user_region_id').format(user_id) + " AND rg.zone_id in {}".format(
                _split(args.get('zone'))))
        zone_region = _split(zone_region[0].get('region_id'))
        if zone_region:
            r_join = " AND md.region in {}".format(zone_region)
        else:
            _query = query_parser.get('users', '_get_zone_region_map_concat') + " WHERE rg.zone_id in {}".format(
                _split(args.get('zone')))
            region = _get_result_as_dict(_query)
            if region[0].get('region_id'):
                r_join = " AND md.region in {}".format(_split(region[0].get('region_id')))
    if args.get('region'):
        r_join = " AND md.region in {}".format(_split(args.get('region')))
    return r_join


def _disbursed_details(date_col=None, _from=None, _to=None, product=None):
    _query_join = ''
    _join = ''
    _query = query_parser.get('dealership', '_get_loan_disbursement_id')
    sanc_query = query_parser.get('dealership', '_get_disbursed_sum')
    if _from:
        _query_join = " WHERE disbursement_date BETWEEN '{0}' AND '{1}'".format(_from, _to)
        sanc_query += " WHERE disbursement_date BETWEEN '{0}' AND '{1}'".format(_from, _to)
        _join = " CAST({0} as date) BETWEEN '{1}' AND '{2}' AND".format(date_col, _from, _to)
    if product:
        if _from:
            _query_join = " LEFT JOIN t_dealership_loans td ON td.id=tdld.loan_id WHERE tdld.disbursement_date " \
                          "BETWEEN '{0}' AND '{1}' AND product_id IN {2}".format(_from, _to, product)
        else:
            _query_join = " LEFT JOIN t_dealership_loans td ON td.id=tdld.loan_id WHERE product_id IN {0}" \
                .format(product)
    if _query_join:
        _query += _query_join
    res = mydb.run_query(mydb.SELECT, _query)
    sanc_query += " GROUP BY loan_id "
    if _from:
        if res[0].get('id'):
            sanc_query += " HAVING loan_id IN ({}) ORDER BY loan_id".format(res[0].get('id'))
    return sanc_query, _join


def _get_loan_count(data=None, args=None, user_id=None):
    result = {}
    _args = {}
    _args.update({"from": args.get("from"), "to": args.get("to"), "zone": args.get("zone"),
                  "region": args.get("region"), "product": args.get("product"),
                  "account_type": args.get("account_type")})
    if _args:
        for status in data:
            _args.update({"status": status[0]})
            query, a, b = _get_loan_stats(args=_args, user_id=user_id)
            loans_data = mydb.run_query(mydb.SELECT, query)
            result.update({status[0] + "_count": len(loans_data)})
            if len(status) > 1:
                amount_sum = 0
                if loans_data:
                    df = pd.DataFrame(loans_data)
                    amount_sum = df[status[1]].sum()
                result.update({status[2]: str(amount_sum)})
        return result


@app.route('/api/metrics/loan/stats', methods=['GET'])
@jwt_required
def _loan_stats():
    if request.method == 'GET':
        data = [['submitted'], ['loan_review', "amount_requested", "amount_requested_review"],
                ['loan_approval', "amount_requested", "amount_requested"],
                ['approved', "amount_approved", "amount_approved"],
                ['disbursement_approval', "amount_approved", "amount_disbursement_approval"],
                ['disbursement_approved', "amount_approved", "amount_disbursement_approved"],
                ['disbursed', "actual_amount_disbursed", "actual_amount_disbursed"], ['rejected']]
        data = _get_loan_count(data, request.args, get_jwt_identity())
        return jsonify({"status": "SUCCESS", "data": [data]})


def handle_redis_request(query):
    return redis_obj.get_data_from_redis(query)


def update_redis_from_query(section,option,data_to_format):
    data = _lms_data_handler(section,option,data_to_format)
    if data:
        try:
            redis_obj.update_query_values_to_redis(query_parser.get(section,option).format(**data_to_format), data)
        except Exception as e:
            logger.error('Error while fetch data from oracle-> {}'.format(e))


@app.route('/api/redis/refresh', methods=['POST'])
@jwt_required
def redis_refresh_keys():
    @copy_current_request_context
    def redis_refresh_key_thread():
        data = _get_result_as_dict(query_parser.get('general', '_get_external_dashboard_data'))
        for value in data:
            update_redis_from_query('lms_queries',value.get('query_key'),{'tbl_name':value.get('default_name')})
            update_redis_from_query('lms_queries',value.get('query_key'),{'tbl_name':value.get('external_name')})
    thread = Thread(target=redis_refresh_key_thread)
    thread.start()
    return jsonify({'status': 'SUCCESS', 'message': 'Key refreshed successfully.'})


def lms(query_name):
    data = _get_result_as_dict(
        query_parser.get('general', '_get_external_dashboard_data') + " WHERE QUERY_KEY = '{}'".format(query_name))
    if request.args.get('external'):
        if str(_get_user_role(get_jwt_identity())) in EXTERNAL_DASHBOARD_ROLE_ACCESS_LIST:
            return handle_redis_request(
                query_parser.get('lms_queries', query_name).format(tbl_name = data[0].get('external_name')))
    return handle_redis_request(query_parser.get('lms_queries', query_name).format(tbl_name = data[0].get('default_name')))


@app.route('/api/business/metrics/ls1', methods=['GET'])
@jwt_required
def _business_metrics_lsone():
    return jsonify(
        {"status": "SUCCESS", "data": lms('_get_metrics_v_lsone')})


@app.route('/api/business/metrics/ls2', methods=['GET'])
@jwt_required
def _business_metrics_lstwo():
    return jsonify(
        {"status": "SUCCESS", "data": lms('_get_metrics_v_lstwo')})


@app.route('/api/app/dpd/region', methods=['GET'])
@jwt_required
def dpd_dashboard_region():
    if request.method == 'GET':
        return jsonify({"status": "SUCCESS", "data": modify_res(lms('_get_region_dpd'))})


@app.route('/api/app/dpd/omc', methods=['GET'])
@jwt_required
def dpd_dashboard_omc():
    if request.method == 'GET':
        return jsonify({"status": "SUCCESS", "data": modify_res(lms('_get_omc_dpd'))})


def modify_res(data_list=None):
    res = []
    for data in data_list:
        val = {}
        val_list = []
        if "omc" in data:
            val.update({"label": data.get("omc")})
            data.pop("omc")
        else:
            val.update({"label": data.get("cust_region")})
            data.pop("cust_region")
        for k, v in data.items():
            val_list.append({"label": k, "value": v})
        val.update({"data": val_list})
        res.append(val)
    return res


@app.route('/api/business/property', methods=['GET', 'POST'])
def _get_business_property():
    if request.method == 'GET':
        return _get_result(query_parser.get('business_property', '_get_business_property'))
    elif request.method == 'POST':
        data = request.get_json()
        return _is_rows_affected(
            (query_parser.get('business_property', '_post_business_property')).format(data.get('property_name')))
    else:
        return jsonify(error_parser.get('invalid', '_invalid_request')), 200


'''Do not add auth header to this API as it is used in signup flow'''
@app.route('/api/business/types', methods=['GET', 'POST'])
@app.route('/api/business/types/<id>', methods=['POST', 'DELETE'])
def _business_types(id=None):
    if request.method == 'GET':
        return _get_result(query_parser.get('business_type', '_get_business_type'))
    elif request.method == 'POST':
        data = request.get_json()
        if id:
            cols = mydb._get_columns("m_business_types")
            query = mydb._gen_update_query('m_business_types', cols, data)
            return _execute_query(mydb.UPDATE, query + "WHERE id={}".format(id))
        return _is_rows_affected(
            (query_parser.get('business_type', '_post_business_type')).format(data.get('name')))
    elif request.method == 'DELETE':
        query = "DELETE FROM m_business_types WHERE id={}".format(id)
        return _execute_query(mydb.DELETE, query)
    else:
        return jsonify(error_parser.get('invalid', '_invalid_request'), 200)


@app.route('/api/loan/types', methods=['GET', 'POST'])
@app.route('/api/loan/types/<id>', methods=['POST', 'DELETE'])
@jwt_required
def _loan_types(id=None):
    if request.method == 'GET':
        return _get_result(query_parser.get('loan_type', '_get_loan_type'))
    elif request.method == 'POST':
        data = request.get_json()
        if id:
            data.update({"last_modified_by": get_jwt_identity()})
            query = mydb._gen_update_query("m_loan_types", list(data), data)
            return _execute_query(mydb.UPDATE, query + " WHERE loan_id={}".format(id))
        return _is_rows_affected(
            (query_parser.get('loan_type', '_post_loan_type')).format(data.get('name')))
    elif request.method == 'DELETE':
        query = "DELETE FROM m_loan_types WHERE loan_id = {}".format(id)
        return _execute_query(mydb.DELETE, query)
    else:
        return jsonify(error_parser.get('invalid', '_invalid_request'), 200)


@app.route('/api/relationships', methods=['GET'])
def relationships():
    if request.method == 'GET':
        return _get_result("SELECT label, value from m_relationships");


@app.route('/api/submit/dealership/<int:dealership_id>', methods=['POST'])
@jwt_required
def _submit_application(dealership_id=None):
    if dealership_id:
        request_data = request.get_json()
        if request_data.get('otp'):
            _status, _msg = verify_otp(request_data.get('mobile'), request_data.get('otp'))
            if not _status:
                return jsonify({'status': 'ERROR', 'message': _msg})
            # TODO
            # Get loan_id in request while submitting the application from mobile app
            loan_status = mydb.run_query(mydb.SELECT,
                                         query_parser.get("dealership", "_get_active_loan_status").format(
                                             dealership_id))
            if loan_status and loan_status[0].get("status"):
                return jsonify({"status": "ERROR", "message": "Application is already submitted. "+_support_message})
            files_to_attach = []
            files_name = []
            loan_id = request_data.get('loan_id')
            profile_state = _check_profile_completion_status(dealership_id).get_json()
            if profile_state.get('completion_status'):
                msg = {}
                data = {}
                _target_file_path = app.config['TARGET_FILE_PATH'] + "/{}/".format(str(dealership_id))
                _file_name = "{}_loan_application.html".format(dealership_id)
                file_to_attach = _target_file_path + "{}_loan_application.pdf".format(dealership_id)
                ds_query = query_parser.get('dealership', '_get_dealership_details_by_id').format(dealership_id)
                dl_query = query_parser.get('dealers', '_get_dealer_details_by_id').format(dealership_id)
                dbd_query = query_parser.get('dealership', '_get_bank_details').format(dealership_id)
                bd_query = query_parser.get('dealership', '_get_dealership_business_age_by_id').format(dealership_id)
                dealership_details = mydb.run_query(mydb.SELECT, ds_query)
                dealer_details = mydb.run_query(mydb.SELECT, dl_query)
                bank_details = mydb.run_query(mydb.SELECT, dbd_query)
                business_details = mydb.run_query(mydb.SELECT, bd_query)
                logger.debug("Loan application submission......")
                if dealership_details and dealership_details:
                    data.update(dealership_details[0])
                if dealer_details and dealer_details:
                    data.update(dealer_details[0])
                if bank_details and bank_details:
                    data.update(bank_details[0])
                if business_details and business_details:
                    data.update(business_details[0])
                _application_form = _find_and_replace(app.config['APPLICATION_TEMPLATE'], _target_file_path, _file_name,
                                                      data)
                if _application_form:
                    with open(_application_form) as fin:
                        pdfkit.from_file(fin, os.path.join(file_to_attach), options=options,
                                         configuration=_wkhtml_config)
                msg.update({"subject": "Application form for Loan request by {} ({})".format(
                    dealership_details[0].get('name'), dealership_id)})
                msg.update({
                    "body": "Dear Sir/Madam,\nGreetings!\n\nA new application for loan has been submitted by {} (dealership ID: {})".format(
                        dealership_details[0].get('name'), dealership_id)})
                fo_rm_email_list = mydb.run_query(mydb.SELECT,
                                                  query_parser.get('users', '_get_fo_rm_email_by_dealership_id').format(
                                                      dealership_id))
                _email_recipients = []
                _email_recipients.extend(recipients)
                for email_id in fo_rm_email_list:
                    _email_recipients.append(email_id.get('email'))
                msg.update({"recipients": _email_recipients})
                email_status = _send_mail(msg)
                result = update_loan_status_and_remarks({"status": "pre_submit"}, loan_status[0].get('id'),
                                                        dealership_id=dealership_id)
                if result:
                    mydb.run_query(mydb.UPDATE,
                                   query_parser.get('dealership', '_update_loan_status_submit').format(dealership_id))
                return jsonify({"status": "SUCCESS", "message": "Form submitted successfully",
                                "email_status": email_status.get_json(), "update_result": result})
            else:
                return jsonify({"status": "ERROR", "data": profile_state,
                                "message": "Please check if Dealership, Dealers and Loan request is filled."})
    return jsonify(error_parser.get('invalid', '_id_details_missing'), 200)


@app.route('/api/dealership/<int:dealership_id>/loan/<int:loan_id>/resubmit', methods=['POST'])
@jwt_required
def _resubmit_application(dealership_id=None, loan_id=None):
    msg = {}
    msg.update({"recipients": recipients})
    msg.update({
        "subject": "Loan application with loan number({1}) of dealership({0}) is re-submitted for processing - Reg.".format(
            dealership_id, loan_id)})
    msg.update({
        "body": "Dear Team,\n"
                "The following loan application has been resubmitted to submitted queue for re-processing.\n\n"
                "https://mdm.petromoney.in/#/dealership/{0}".format(dealership_id)})
    result = update_loan_status_and_remarks({"status": "submitted"}, loan_id, dealership_id=dealership_id,
                                            status='resubmit')
    if result:
        email_status = _send_mail(msg)
        return jsonify({"status": "SUCCESS", "message": "Loan application re-submitted successfully",
                        "email_status": email_status.get_json(), "result": result})
    else:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_incomplete_details')})


@app.route('/api/loans/reason', methods=['GET', 'POST'])
@app.route('/api/loans/reason/<int:id>', methods=['POST', 'DELETE'])
@jwt_required
def loan_reject_reason(id=None):
    if request.method == 'POST':
        data = request.get_json()
        data.update({'last_modified_by': get_jwt_identity()})
        if id:
            return _execute_query(mydb.UPDATE,
                                  mydb._gen_update_query('m_reject_reason', list(data), data) + " WHERE id={0}".format(
                                      id), success_message='Reason modified successfully.')
        if data.get('reason') and data.get('code') and data.get('description'):
            return _execute_query(mydb.INSERT, mydb._gen_insert_query('m_reject_reason', data),
                                  success_message='Reason added successfully.')
    elif request.method == 'GET':
        data = _get_result_as_dict(query_parser.get('dealership', '_get_loan_reject_reason'))
        for i in data:
            try:
                i['list'] = json.loads(i.get('list'))
            except ValueError:
                pass
        return jsonify({'status': 'SUCCESS', 'data': data})
    elif request.method == 'DELETE':
        if id:
            return _execute_query(mydb.DELETE, "DELETE FROM m_reject_reason WHERE id='{0}'".format(id))
    return jsonify({'status': 'ERROR', 'message': 'Missing required key.'})


def get_next_state_based_on_current_state(current_state):
    status = ['pre_submit', 'submitted', 'loan_review', 'loan_approval', 'approved', 'disbursement_approval',
              'disbursement_approved',
              'disbursed', 'disbursed']
    if current_state in status:
        index = status.index(current_state)
        return status[index + 1]
    logger.error("Unknown Status : '{}' not found in existing acceptable loans status list.".format(current_state))
    abort(jsonify(status="ERROR", message="Unable to process the request."+_support_message))


def update_loan_status_and_remarks(data, loan_id, query_remarks=None, user_id=None, dealership_id=None, status=None):
    cols = mydb._get_columns("t_dealership_loans")
    loan_update_query = mydb._gen_update_query("t_dealership_loans", cols, data)
    result = mydb.run_query(mydb.UPDATE, loan_update_query + " WHERE id={}".format(loan_id))
    if query_remarks:
        remarks_result = mydb.run_query(mydb.INSERT, query_remarks)
    if status:
        data.update({'status': status})
    whatsapp_data = _get_result_as_dict(
        query_parser.get('whatsapp_notification', '_get_dealership_name_product_region_by_dealership_id').format(
            dealership_id))[0]
    whatsapp_data.update({'status': data.get('status'), 'amount_approved': data.get('amount_approved')})
    if data.get('status') in ['submitted', 'pre_submit']:
        whatsapp_data.update(
            _get_result_as_dict(query_parser.get('users', '_get_user_details_by_id').format(get_jwt_identity()))[0])
    if data.get('status') == 'rejected':
        whatsapp_data.update(_get_result_as_dict(
            query_parser.get('whatsapp_notification', '_get_description_by_reason_id').format(data.get('reason_id')))[
                                 0])
    _whatsapp_notification(whatsapp_data, data.get('status'), dealership_id=dealership_id, user_id=user_id)
    return result


@app.route('/api/dealership/<int:dealership_id>/loan/<int:loan_id>/approval', methods=['POST', 'DELETE'])
@jwt_required
def _send_application_approval(dealership_id=None, loan_id=None):
    if dealership_id:
        if request.method == 'POST':
            data = request.get_json()
            data.update({'dealership_id': dealership_id, 'loan_id': loan_id, 'last_modified_by': get_jwt_identity()})
            now = datetime.datetime.now()
            _loan_status = mydb.run_query(mydb.SELECT,
                                          query_parser.get('dealership', '_get_loan_status').format(loan_id))
            current_loan_status = _loan_status[0].get('status')
            next_state = get_next_state_based_on_current_state(current_loan_status)
            data.update({'status': next_state})
            query_remarks = mydb._gen_upsert_query("t_dealership_loan_remarks",
                                                   mydb._get_columns("t_dealership_loan_remarks"), data)
            if next_state == "submitted" and current_loan_status == "pre_submit":
                current_user = _get_result_as_dict(
                    query_parser.get('users', '_get_user_role').format(get_jwt_identity()))
                if current_user and current_user[0].get('role_id') in [1, 10, 11]:
                    return jsonify({"status": "SUCCESS", "message": "Loan moved to submitted successfully",
                                    "result": update_loan_status_and_remarks(data, loan_id,
                                                                             dealership_id=dealership_id)})
                return jsonify({"status": "ERROR", "message": "Unauthorized request. "+_support_message})
            if next_state == "loan_review" and current_loan_status == "submitted":
                _check_fields_in_request_data(['reviewer_id'], data)
                result = update_loan_status_and_remarks(data, loan_id, query_remarks, user_id=data.get('reviewer_id'),
                                                        dealership_id=dealership_id)
                return jsonify(
                    {"status": "SUCCESS", "message": "Loan review request submitted successfully", "result": result})

            if next_state == "loan_approval" and current_loan_status == 'loan_review':
                _check_fields_in_request_data(['approver_id'], data)
                current_user = \
                    _get_result_as_dict(query_parser.get('users', '_get_user_role').format(get_jwt_identity()))[0]
                if current_user.get('role_id') == 1 or get_jwt_identity() == _loan_status[0].get('reviewer_id'):
                    result = update_loan_status_and_remarks(data, loan_id, query_remarks,
                                                            user_id=data.get('approver_id'),
                                                            dealership_id=dealership_id)
                    return jsonify({"status": "SUCCESS", "message": "Loan approval request submitted successfully."})
                return jsonify({"status": "ERROR", "message": "Unauthorized request. "+_support_message})

            elif next_state == "approved" and current_loan_status == "loan_approval":
                current_user = \
                    _get_result_as_dict(query_parser.get('users', '_get_user_role').format(get_jwt_identity()))[0]
                if current_user.get('role_id') == 1 or get_jwt_identity() == _loan_status[0].get('approver_id'):
                    data.update({'loan_approved_rejected_date': now.strftime('%Y-%m-%d %H:%M:%S')})
                    result = update_loan_status_and_remarks(data, loan_id, query_remarks, dealership_id=dealership_id)
                    return jsonify({"status": "SUCCESS", "message": "Loan approval request submitted successfully."})
                return jsonify({"status": "ERROR", "message": "Unauthorized request. "+_support_message})

            elif next_state == "disbursement_approval" and current_loan_status == "approved":
                result = update_loan_status_and_remarks(data, loan_id, query_remarks, dealership_id=dealership_id)
                return jsonify(
                    {"status": "SUCCESS", "message": "Approval request submitted successfully", "result": result})

            elif next_state == "disbursement_approved" and current_loan_status == "disbursement_approval":
                data.update({'loan_disbursement_approved_rejected_date': now.strftime('%Y-%m-%d %H:%M:%S')})
                result = update_loan_status_and_remarks(data, loan_id, query_remarks, dealership_id=dealership_id)
                return jsonify({"status": "SUCCESS", "message": "Loan disbursement request approved successfully",
                                "result": result})

            elif next_state == "disbursed" and current_loan_status == "disbursement_approved":
                data.update({'loan_disbursed_date': now.strftime('%Y-%m-%d %H:%M:%S')})
                _check_fields_in_request_data(['disbursement_date'], data)
                disbursement_details_cols = ["loan_id", "applicant_code", "prospect_code", "disbursement_date",
                                             "amount", "disbursement_status"]
                disbursement_details_query = mydb._gen_insert_query_exclude_cols(
                    "t_dealership_loan_disbursement_details", disbursement_details_cols, data)
                disbursement_details_result = mydb.run_query(mydb.INSERT, disbursement_details_query)
                _map_disbursement_details(dealership_id, data)
                _map_los_to_lms(dealership_id, data.get('applicant_code'), get_jwt_identity())
                dealer_data = _get_result_as_dict(
                    "SELECT first_name, last_name, email, mobile, 13 as role_id FROM m_dealers WHERE is_active = 1 and dealership_id={}".format(
                        dealership_id))[0]
                _dealer_user_account = _signup(dealer_data)
                result = update_loan_status_and_remarks(data, loan_id, query_remarks, dealership_id=dealership_id)
                return jsonify(
                    {"status": "SUCCESS", "message": "Loan has been disbursed successfully", "result": result})

            elif next_state == "disbursed" and current_loan_status == "disbursed":
                disbursement_details_cols = ["loan_id", "applicant_code", "prospect_code", "disbursement_date",
                                             "amount", "disbursement_status"]
                disbursement_details_upsert_query = mydb._gen_upsert_query("t_dealership_loan_disbursement_details",
                                                                           disbursement_details_cols, data)
                details_upsert_result = mydb.run_query(mydb.INSERT, disbursement_details_upsert_query)
                _map_disbursement_details(dealership_id, data)
                return jsonify({"status": "SUCCESS", "message": "Loan has been disbursed successfully",
                                "result": details_upsert_result})

        elif request.method == "DELETE":
            data = request.get_json()
            _applicant_code = data.get('applicant_code')
            _prospect_code = data.get('prospect_code')
            if all([_applicant_code, _prospect_code]):
                _hide_details = mydb.run_query(mydb.DELETE, query_parser.get('dealership',
                                                                             '_remove_loan_disbursement_details').format(
                    loan_id, _applicant_code, _prospect_code))
                return jsonify({"status": "SUCCESS", "message": "Loan disbursement detail removed."})
            else:
                return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_incomplete_details')})
        else:
            return jsonify(
                {"status": "ERROR", "message": error_parser.get('invalid', '_incorrect_approval_request')})


def _map_los_to_lms(dealership_id, applicant_code, last_modified_by):
    if _los_lms_mapping_exists(dealership_id, applicant_code):
        logger.debug("Mapping already exists. Hence, skipping the execution.")
    else:
        data = {}
        data.update(
            {"dealership_id": dealership_id, "applicant_code": applicant_code, "last_modified_by": last_modified_by})
        query = mydb._gen_insert_query('t_los_lms_map', data)
        affected_rows = mydb.run_query(mydb.INSERT, query)
        if affected_rows:
            logger.debug("Successfully mapped dealership_id - {0} to the applicant code - {1}".format(dealership_id,
                                                                                                      applicant_code))
        else:
            logger.debug(
                "Could not map dealership_id - {0} to the applicant code - {1}.".format(dealership_id, applicant_code))


def _los_lms_mapping_exists(dealership_id, applicant_code):
    query = query_parser.get('lms', '_los_lms_exists').format(dealership_id, applicant_code)
    return mydb.run_query(mydb.SELECT, query)[0].get('exist')


def _whatsapp_notification(whatsapp_data, status, dealership_id, user_id=None):
    details = _get_result_as_dict(
        query_parser.get('whatsapp_notification', '_get_template_id_and_roles_from_status').format(status))
    if details:
        details = details[0]
        payload = {"template": {
            "body": [],
            "langCode": "en",
            "templateId": details.get('template_name')
        }}
        for key in details.get('payload_keys').split(','):
            payload['template']['body'].append({"type": "text", "text": whatsapp_data.get(key, key)})
        mobile = []
        if user_id:
            mobile.extend(_get_result_as_dict(query_parser.get('users', '_get_user_details_by_id').format(user_id)))
        if details.get('allowed_roles'):
            mobile.extend(_get_result_as_dict(
                query_parser.get('whatsapp_notification', '_get_mobile_numbers_from_role_id').format(dealership_id,
                                                                                                     details.get(
                                                                                                         'allowed_roles'))))
        if details.get('notify_submitted_user'):
            mobile.extend(
                _get_result_as_dict(query_parser.get('users', '_get_user_details_by_id').format(get_jwt_identity())))
        if details.get('notify_dealers'):
            mobile.extend(_get_result_as_dict(
                query_parser.get('whatsapp_notification', '_get_dealer_mobile_by_dealership_id').format(dealership_id)))
        mobile = [i.get('mobile') for i in mobile]
        whatsapp_add_optin(mobile)
        for i in set(mobile):
            _push_to_whatsapp(to=i, type='template', message_content=payload)


@app.route('/api/dealership/<int:dealership_id>/loan/<int:loan_id>/reject', methods=['POST'])
@jwt_required
def reject_loan_application(dealership_id=None, loan_id=None):
    data = request.get_json()
    now = datetime.datetime.now()
    _check_fields_in_request_data(['reason_id'], data)
    reason_id = ",".join([str(i) for i in data.get('reason_id')])
    data.update({'status': 'rejected', 'loan_approved_rejected_date': now.strftime('%Y-%m-%d %H:%M:%S'),
                 'reason_id': reason_id})
    result = update_loan_status_and_remarks(data, loan_id, query_remarks=None, dealership_id=dealership_id)
    return jsonify({"status": "SUCCESS", "message": "Loan application has been rejected.", "result": result})


def _map_disbursement_details(dealership_id, data):
    logger.debug("updating disbursement details to lms......")
    dealer_data = _get_result_as_dict("SELECT md.name, r.name as region_name, o.name as omc FROM m_dealership md "
                                      "LEFT JOIN m_regions r ON md.region=r.id "
                                      "LEFT JOIN m_omcs o ON md.omc=o.id WHERE md.id={0}".format(dealership_id))[0]
    stmt = query_parser.get('lms', '_upsert_disbursement_details').format(data.get('prospect_code'),
                                                                          data.get('applicant_code'),
                                                                          dealer_data.get('name'),
                                                                          data.get('disbursement_date'),
                                                                          data.get('amount'),
                                                                          datetime.datetime.strptime(
                                                                              data.get('disbursement_date'),
                                                                              "%Y/%m/%d").strftime("%b").upper(),
                                                                          dealership_id,
                                                                          dealer_data.get('region_name'),
                                                                          dealer_data.get('region_name'),
                                                                          dealer_data.get('omc'))

    return _execute_lms_query(stmt)


@app.route('/api/checklist/<int:dealership_id>', methods=['GET'])
@app.route('/api/checklist/<int:dealership_id>/doc/<int:doc_id>', methods=['GET', 'POST'])
@app.route('/api/checklist/<int:dealership_id>/doc/<int:doc_id>/<int:id>', methods=['POST'])
@jwt_required
def _get_document_checklist(dealership_id=None, doc_id=None, dealer_id=None, id=None):
    if dealership_id:
        if dealer_id:
            if request.method == 'GET':
                return _get_result(
                    query_parser.get('checklist', '_get_documents_checklist_status_dealer_id').format(dealership_id,
                                                                                                      dealer_id))
        else:
            if request.method == 'GET':
                query = query_parser.get('checklist', '_get_documents_checklist_status').format(dealership_id)
                res_data = mydb.run_query(mydb.SELECT, query)
                _formatted_file_data = _format_files_data(res_data, 'doc_id')
                return jsonify({'status': 'SUCCESS', 'data': _formatted_file_data})

        if request.method == 'POST':
            """This function is used to rename the existing file in document checklist."""
            if id:
                try:
                    data = request.get_json()
                    file_path = '/'.join(data.get('file_url').split('/')[3:][:-1])
                    old_file = '/'.join(data.get('file_url').split('/')[3:])
                    file_name = data.get('file_name').replace(" ", "_")
                    file_url = '/'.join(data.get('file_url').split('/')[:-1]) + "/" + file_name
                    client = boto3.client('s3')
                    response = client.copy_object(Bucket=dealership_docs_bucket,
                                                  CopySource=dealership_docs_bucket + "/" + old_file,
                                                  Key=file_path + "/" + file_name)
                    if not response.get('ResponseMetadata').get('HTTPStatusCode') == 200:
                        return jsonify({'status': 'ERROR', 'message': 'Please re-upload the file.'})
                    client.delete_object(Bucket=dealership_docs_bucket, Key=old_file)
                    _execute_query(mydb.UPDATE,
                                   query_parser.get('checklist', '_update_document_name').format(file_url, dealership_id,
                                                                                                 data.get('file_id')))
                    return jsonify({'status': 'SUCCESS', 'message': 'Document Renamed Successfully'})
                except Exception as e:
                    logger.debug('File rename error because: {}'.format(e))
                    return jsonify({'status':"ERROR",'message':"Couldn't handle the request please try again."})
            data = {}
            '''Marking for updation, need to remove status check and do doc check using the _s3_file_url list length'''
            _status = False
            _s3_file_url = []
            _split_file_urls = []

            if request.files:
                try:
                    for file in request.files:
                        _url, message = _file_upload(request.files.getlist(file), origin_id=dealership_id,
                                                     doc_id=doc_id, type='dealers')
                        if _url:
                            if len(_url.split(" ")) >= 1:
                                _split_file_urls = _url.split(" ")
                                _s3_file_url.append(_split_file_urls)
                            else:
                                _s3_file_url.append(_url)
                            if id is None:
                                for _split_url in _split_file_urls:
                                    if dealer_id is None:
                                        _query = query_parser.get('checklist', '_post_documents_checklist_status') \
                                            .format(dealership_id, 0, doc_id, 1, _split_url)
                                    else:
                                        _query = query_parser.get('checklist', '_post_documents_checklist_status') \
                                            .format(dealership_id, dealer_id, doc_id, 1, _split_url)
                                    _query_status = _execute_query(mydb.INSERT, _query)
                                    data.update(
                                        {'dealership_id': dealership_id, 'dealer_id': dealer_id, 'doc_id': doc_id,
                                         'url': _s3_file_url})
                            else:
                                _query = query_parser.get('checklist', '_update_documents_checklist_status').format(1,
                                                                                                                    _url,
                                                                                                                    id)
                                _query_status = _execute_query(mydb.UPDATE, _query)
                                logger.debug("Document checklist updated for dealership-id %s",dealership_id)
                                data.update(
                                    {'dealership_id': dealership_id, 'dealer_id': dealer_id, 'doc_id': doc_id,
                                     'url': _s3_file_url})
                        else:
                            return jsonify({'status': 'SUCCESS', 'message': "No files updated."})
                    return jsonify(
                        {'status': 'SUCCESS', 'message': "File uploaded successfully", 'data': data})
                except OSError as e:
                    logger.debug('Error: {}'.format(e))
                    return jsonify({"status": "FAILURE",
                                    "message": "Details could not be updated as file can't be uploaded. "
                                               "Please email the document to sales@petromoney.co.in"})
            else:
                return jsonify({"status": "FAILURE",
                                "message": "No files in the request to upload."})
    else:
        return jsonify({'status': 'ERROR', 'message': error_parser.get('invalid', '_invalid_request')})


@app.route('/api/checklist/<int:dealership_id>', methods=['DELETE'])
@jwt_required
def _remove_documents(dealership_id=None):
    data = request.get_json()
    _ids = data.get("id")
    _ids = tuple(_ids) if len(_ids) > 1 else "(" + str(_ids[0]) + ")"
    _result = mydb.run_query(mydb.UPDATE,
                             query_parser.get('checklist', '_disable_documents').format(dealership_id, _ids))
    return jsonify({'status': 'SUCCESS', 'message': 'Document(s) removed successfully.', 'data': _result})


@app.route('/api/checklist/<int:dealership_id>/doc/<int:id>', methods=['DELETE'])
@jwt_required
def _remove_document(dealership_id=None, id=None):
    _result = mydb.run_query(mydb.UPDATE, query_parser.get('checklist', '_disable_document').format(dealership_id, id))
    return jsonify({'status': 'SUCCESS', 'message': 'Document removed successfully.', 'data': _result})


@app.route('/api/dealership/<int:dealership_id>/passbook', methods=['GET'])
@app.route('/api/passbook/dealership/<int:dealership_id>', methods=['GET'])
@jwt_required
def _get_dealership_passbook(dealership_id=None):
    if dealership_id:
        data = _lms_data_handler('dealership','passbook_by_dealership_id',data = {'dealership_id': dealership_id})
        if data:
            if request.args.get('send', 0):
                _data = pd.DataFrame(data)
                if len(_data):
                    file_name = secure_filename(datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S') + ".csv")
                    _data.to_csv('data/' + file_name, index=False)
                    file = open("data/" + file_name)
                    if request.args.get('download', 0):
                        _s3_file_prefix = "dealership/" + str(dealership_id) + '/' + str('passbook') + '/'
                        _upload_status, _uploaded_file_url = _s3_file_upload(_s3_file_prefix,
                                                                             file_name,
                                                                             dealership_docs_bucket,
                                                                             file)
                        file.close()
                        os.remove("data/" + file_name)
                        if _upload_status:
                            return jsonify({'status': 'SUCCESS', 'data': [_uploaded_file_url]})
                        return jsonify({'status': 'ERROR', 'message': 'Unable to Download data'})
                    mail = {}
                    query = query_parser.get('dealership', '_get_dealership_main_applicant_mail').format(dealership_id)
                    email = _get_result_as_dict(query)
                    email_list = []
                    for i in range(len(email)):
                        email = email[i].get('email')
                        email_list.append(email)
                    if len(email) > 0:
                        mail.update({'subject': 'petromoney passbook report',
                                     'body': """Dear Customer,\nGreetings from Petromoney!\nPlease find attached e-Statement of your passbook report as requested.\nThanks,\nTeam Petromoney""",
                                     'recipients': email_list

                                     })
                        file_to_attach = [file.name]
                        file_names = [file_name]
                        mail_status = _send_mail(mail, attachment=file_to_attach, file_name=file_names,
                                                 file_type="text/csv")
                        file.close()
                        os.remove("data/" + file_name)
                        if mail_status.get_json().get('delivery'):
                            return jsonify({'status': 'SUCCESS', 'message': 'Mail sent successfully.'})
                    return jsonify({'status': 'ERROR', 'message': "Unable to send mail."})
                return jsonify({'status': 'ERROR', 'message': 'No transaction available.'})
            return jsonify({"status": "SUCCESS", "data": data})
        return jsonify({'status': 'ERROR', 'message': 'No data found!'})
    else:
        return jsonify(error_parser.get('invalid', '_id_details_missing')), 200


def _check_fields_in_request_data(mandatory_fields, data):
    missing_fields = [item for item in mandatory_fields if not data.get(item)]
    if missing_fields:
        missing_fields_str = ', '.join(missing_fields)
        abort(jsonify(status="ERROR", message=f"Missing mandatory fields: {missing_fields_str}."))


@app.route('/api/transport/owners', methods=['GET'])
@app.route('/api/transport/owner/<int:t_owner_id>', methods=['GET'])
@jwt_required
def _get_transport_owners(t_owner_id=None):
    if t_owner_id:
        return _get_result(query_parser.get('transporters', '_get_transport_owner_by_id').format(t_owner_id))
    else:
        return _get_result(query_parser.get('transporters', '_get_transport_owners').format(get_jwt_identity()))


@app.route('/api/transport/owners/<int:dealership_id>', methods=['GET'])
@jwt_required
def _get_transport_owners_by_dealership_id(dealership_id=None):
    if dealership_id:
        return _get_result(
            query_parser.get('transporters', '_get_transport_owners_by_dealership_id').format(dealership_id))


@app.route('/api/transport/owner', methods=['POST'])
@app.route('/api/transport/owner/<int:t_owner_id>', methods=['POST', 'DELETE'])
@jwt_required
def _transport_owners(t_owner_id=None):
    if request.method == 'POST':
        data = format_date_in_data(encrypt_data(dict(request.form)), ['dob'])
        if not data and not bool(request.files):
            return jsonify({'status': 'ERROR', 'message': 'Invalid input,please enter details'})
        if _check_duplicates("t_transport_owners", data, applicant_id=t_owner_id):
            return jsonify({"status": "ERROR", "message": "Duplicate KYC records (Aadhar/PAN/Mobile)"})
        data.update({"last_modified_by": get_jwt_identity()})
        _col_list = mydb._get_columns('t_transport_owners')
        if t_owner_id:
            if bool(request.files):
                _status_, result = _upload_kyc_docs(request.files, origin_id=t_owner_id, type='transport')
                if _status_:
                    data.update(result)
                else:
                    return jsonify({'status': 'ERROR', 'message': result})
            _update_query = mydb._gen_update_query("t_transport_owners", _col_list, data)
            return _is_rows_affected(_update_query + " WHERE t_owner_id={}".format(t_owner_id))
        else:
            _add_query = mydb._gen_insert_query_exclude_cols("t_transport_owners", _col_list, data)
            affected_rows, t_owner_id = mydb.run_query(mydb.INSERT, _add_query, row_insert_id=True)
            if bool(request.files):
                _status_, result = _upload_kyc_docs(request.files, origin_id=t_owner_id, type='transport')
                if _status_:
                    data.update(result)
                else:
                    return jsonify({'status': 'ERROR', 'message': result})
            _update_query = mydb._gen_update_query("t_transport_owners", _col_list, data)
            _is_rows_affected(_update_query + " WHERE t_owner_id={}".format(t_owner_id))
            return jsonify({'status': 'SUCCESS', 'message': 'Transport owner added successfully'})
    elif request.method == 'DELETE':
        data = request.get_json()
        query = query_parser.get('transporters', '_remove_transport_owner_attachment').format(list(data)[0], t_owner_id)
        mydb.run_query(mydb.DELETE, query)
        return jsonify({'status': 'SUCCESS', 'message': 'Attachment removed successfully'})


def _upload_kyc_docs(user_files, origin_id=None, id=None, type=None):
    _file_data = {}
    try:
        for file in user_files:
            if file in list(ALLOWED_KYC_NAMES):
                file_url, message = _file_upload(request.files.getlist(file), origin_id=origin_id, id=id,
                                                 doc_id=ALLOWED_KYC_NAMES[file], type=type)
                if file_url is not None:
                    _file_data.update({file: file_url})
                else:
                    return False, message
            else:
                return False, "Unkown file name"
        return "True", _file_data
    except Exception as e:
        logger.debug('File upload error because: {}'.format(e))
        return False, "File couldn't be uploaded."


@app.route('/api/transport/owner/<int:t_owner_id>', methods=['DELETE'])
@jwt_required
def _disable_transport_owners(t_owner_id=None):
    if t_owner_id:
        _col_list = mydb._get_columns('t_transport_owners')
        _query = mydb._gen_update_query('t_transport_owners', _col_list, {'status': 0})
        return _execute_query(mydb.UPDATE, _query + " WHERE t_owner_id={}".format(t_owner_id))


@app.route('/api/transporters/exceptions', methods=['GET'])
@jwt_required
def _get_transporter_exceptions():
    return _get_result(query_parser.get('transporters', '_get_unmapped_transporters'))


@app.route('/api/transporterslist', methods=["GET"])
@jwt_required
def _get_transporters_list():
    return _get_result(query_parser.get('transporters', '_get_all_transporters'))


@app.route('/api/transporters/<int:transporter_id>', methods=["GET"])
@jwt_required
def _get_transporter_info(transporter_id=None):
    return _get_result(query_parser.get('transporters', '_get_transporter_info_by_id').format(transporter_id))


@app.route('/api/transporters/owner/<int:t_owner_id>', methods=["GET"])
@jwt_required
def _get_transporters(t_owner_id=None):
    return _get_result(query_parser.get('transporters', '_get_all_transports_by_owner_id').format(t_owner_id))


""" 
1.  /api/dealership/<int:dealership_id>/transporters [POST] - it's used to Add the new transpoter under dealership 
    /api/dealership/<int:dealership_id>/transporters [GET]  - it's used to get the all transportes under particular dealership

2.  /api/dealership/<int:dealership_id>/transporters/<int:transporter_id> [POST] - It's used to edit particular transporter
    /api/dealership/<int:dealership_id>/transporters/<int:transporter_id> [GET] - It's used to get the particular transporter under dealership
"""


@app.route('/api/dealership/<int:dealership_id>/transporters', methods=["GET", "POST"])
@app.route('/api/dealership/<int:dealership_id>/transporters/<int:transporter_id>', methods=["GET", "POST", "DELETE"])
@jwt_required
def transporter(dealership_id=None, transporter_id=None):
    if request.method == 'POST':
        """ is get data from multipart form format   """
        data = format_date_in_data(encrypt_data(dict(request.form)), ['doi'])
        data.update({'name': data.get('transporter_name')})
        if transporter_id is None:
            """ is check Pan, Aadhar, GST duplicates """
            if _check_duplicates("t_transports", data, applicant_id=transporter_id):
                return jsonify({"status": "ERROR", "message": "Duplicate KYC records (Aadhar/PAN/Mobile)"})
            """ is used to add user  """
            response = _signup(data).get_json()
            if response.get('status') == 'SUCCESS':
                data.update({"last_modified_by": get_jwt_identity()})
            else:
                return response
            """ is used to add the transporter """
            _query = mydb._gen_insert_query_exclude_cols(
                't_transports', mydb._get_columns('t_transports'), data)
            affected_rows, transporter_id = mydb.run_query(
                mydb.INSERT, _query, row_insert_id=True)
            if transporter_id:
                """ it is used to add the trasporter and dealership  """
                mapped_response, response_msg = dealership_transporter_map(
                    dealership_id, transporter_id, data)
        if bool(request.files):
            _status_, result = _upload_kyc_docs(request.files, origin_id=transporter_id, type='transport')
            if _status_:
                data.update(result)
        """ this function used to edit the user [role_id : 14] data """
        _update_user_data_response, _msg = _update_user_data(
            data, transporter_id)
        """ is used to edit the transporter data"""
        _query = mydb._gen_update_query(
            "t_transports", mydb._get_columns('t_transports'), data)
        mydb.run_query(mydb.UPDATE, _query +
                       " WHERE transporter_id={}".format(transporter_id))
        return jsonify({'status': 'SUCCESS', 'message': 'Transport added successfully'})

    elif request.method == 'GET':
        """ it is transporter get query """
        _get_dealership_mapped_transporter_query = query_parser.get(
            'transporters', '_get_mapped_dealership_and_transportes')
        """ it is used to get the dealership based transporter """
        if dealership_id and not transporter_id:
            _get_dealership_mapped_transporter = _get_result_as_dict(
                _get_dealership_mapped_transporter_query.format(dealership_id))
        # it is used get the particular transporter_id
        elif dealership_id and transporter_id:
            _get_dealership_mapped_transporter_query = _get_dealership_mapped_transporter_query + \
                                                       ' AND dtm.transporter_id = {1} '
            _get_dealership_mapped_transporter = _get_result_as_dict(
                _get_dealership_mapped_transporter_query.format(dealership_id, transporter_id))
        if not _get_dealership_mapped_transporter:
            return jsonify({'status': 'ERROR', 'message': ' The transporter has not mapped in this dealership'})
        return jsonify({'status': 'SUCCESS', 'data': _get_dealership_mapped_transporter})
    # is used to delete the particular transporter_id
    elif request.method == 'DELETE':
        data = request.get_json()
        query = query_parser.get(
            'transporters', '_remove_transporters').format(transporter_id)
        mydb.run_query(mydb.DELETE, query)
        return jsonify({'status': 'SUCCESS', 'message': 'Transporters removed succesfully'})


def _update_user_data(data=None, transporter_id=None):
    """ it's used to edit the user data while edit the particular Transporter.
        because, This transporte also in user Table """

    """ This is used to generate only user field """
    _user_transporter_data = {key: data.get(
        key) for key in USER_MAINAPPLICANT_FIELDS if data.get(key)}
    if _user_transporter_data.get('last_modified_by'):
        _user_transporter_data.pop('last_modified_by')
    if _user_transporter_data:
        transporter_data = _get_result_as_dict(query_parser.get(
            'transporters', '_get_transporter_info_by_id').format(transporter_id))[0]
        _query = mydb._gen_update_query(
            "m_users", mydb._get_columns('m_users'), _user_transporter_data)
        affected_rows = mydb.run_query(
            mydb.UPDATE, _query + " WHERE mobile ='{0}' ".format(transporter_data.get('mobile')))
        if affected_rows > 0:
            return True, 'User data updated successfully'
        else:
            return False, 'user data update failed'


@app.route('/api/dealership/<int:dealership_id>/transporters/<int:transporter_id>/map', methods=["POST"])
@jwt_required
def transpoter_map(dealership_id=None, transporter_id=None):
    """ This API is used to map the Transporter and dealership_id.
    because While transporter signup via user API, that transporter is not mapped to any dealership,
    so this API used to map the transporter  """
    response, _msg = dealership_transporter_map(dealership_id, transporter_id)
    if not response:
        return jsonify({'status': 'ERROR', 'message': _msg})
    return jsonify({'status': 'SUCCESS', 'message': _msg})


def dealership_transporter_map(dealership_id=None, transporter_id=None, data=None):
    """
    This Function is used to map the Transporter and dealership_id.
    because While transporter signup via user API, that transporter is not mapped to any dealership,
    so this API used to map the transporter
    """
    if data is None:
        data = {}
    whatsapp_and_sms_data = {}
    _mapped_transporter_data = _get_result_as_dict(query_parser.get(
        'transporters', '_get_exist_dealership_transporter_map').format(dealership_id, transporter_id))
    if _mapped_transporter_data:
        return False, 'This dealership and Transporter are Already Mapped'
    _get_transporter_data = _get_result_as_dict(query_parser.get(
        'transporters', '_get_transporter_info_by_id').format(transporter_id))[0]
    _get_dealership_data = _get_result_as_dict(query_parser.get(
        'dealership', '_get_dealership_by_id').format(dealership_id))[0]
    whatsapp_and_sms_data.update({"transporter_name": _get_transporter_data.get(
        'name'), "dealership_name": _get_dealership_data.get('name')})
    data.update({'dealership_id': dealership_id,
                 'transporter_id': transporter_id})
    dealership_transporter_map_col_list = mydb._get_columns(
        't_dealership_transporter_map')
    data.update({'dealership_id': dealership_id,
                 'transporter_id': transporter_id})
    _query = mydb._gen_insert_query_exclude_cols(
        't_dealership_transporter_map', dealership_transporter_map_col_list, data)
    affected_rows = mydb.run_query(mydb.INSERT, _query)
    if (affected_rows > 0):
        if data.get("is_active_sms") is True:
            transporter_sms_notification('trans_create_by_dealership', whatsapp_and_sms_data, [
                _get_transporter_data.get('mobile')])
        if data.get("is_active_whatsapp") is True:
            transporters_whatsapp_notification('trans_create_by_dealership', whatsapp_and_sms_data, [
                _get_transporter_data.get('mobile')])
        return True, 'Dealership and transporter mapped successfully.'
    else:
        return False, 'Failed to add the record.'


""" 
    1. /api/dealership/<int:dealership_id>/<int:transporter_id>/passbook [GET] - this API used to get them all 
    transporter Fuel Transaction under the dealership.
    2. /api/transporter/<int:transporter_id>/passbook [GET] -  this API used to get them all Fuel Transaction 
    under the transporter.
"""


@app.route('/api/dealership/<int:dealership_id>/<int:transporter_id>/passbook', methods=["GET"])
@app.route('/api/transporter/<int:transporter_id>/passbook', methods=["GET"])
@jwt_required
def upload_passbook(dealership_id=None, transporter_id=None, vehicle_filter=None):
    if request.method == 'GET':
        _query = query_parser.get('transporters', '_get_transporter_passbook')
        _passbook_data_query = query_parser.get(
            'transporters', '_get_transporter_passbook_file')
        from_date = request.args.get('from')
        to_date = request.args.get('to')
        if from_date and from_date == to_date:
            to_date = _increment_date(to_date)
        if request.args.get('vehicle_no'):
            vehicle_no = request.args.get('vehicle_no')
            vehicle_filter = True
        if from_date and to_date:
            if vehicle_filter:
                query = _query + \
                        " and (tpl.bill_date BETWEEN '{1}' and '{2}') and tpl.vehicle_number LIKE '%{3}%' "
                _query = query.format(
                    transporter_id, from_date, to_date, vehicle_no)
                passbook_data_query = _passbook_data_query + \
                                      " and (tpl.bill_date BETWEEN '{1}' and '{2}') and tpl.vehicle_number LIKE '%{3}%' "
                _passbook_data_query = passbook_data_query.format(
                    transporter_id, from_date, to_date, vehicle_no)
                vehicle_filter = False
            else:
                query = _query + " and (tpl.bill_date BETWEEN '{1}' and '{2}')"
                _query = query.format(transporter_id, from_date, to_date)
                passbook_data_query = _passbook_data_query + \
                                      " and (tpl.bill_date BETWEEN '{1}' and '{2}')"
                _passbook_data_query = passbook_data_query.format(
                    transporter_id, from_date, to_date)
        elif vehicle_filter:
            query = _query + " and tpl.vehicle_number LIKE '%{1}%'"
            _query = query.format(transporter_id, vehicle_no)
            passbook_data_query = _passbook_data_query + \
                                  " and tpl.vehicle_number LIKE '%{1}%'"
            _passbook_data_query = passbook_data_query.format(
                transporter_id, vehicle_no)
        else:
            _query = _query.format(transporter_id)
            _passbook_data_query = _passbook_data_query.format(transporter_id)
        if not dealership_id:
            _get_transporter_passbook_query = _query
            _get_transporter_passbook_file_query = _passbook_data_query
        elif transporter_id:
            _get_transporter_passbook_query = (
                    _query + " and tpl.dealership_id = {0}").format(dealership_id)
            _get_transporter_passbook_file_query = (
                    _passbook_data_query + " and tpl.dealership_id = {0}").format(dealership_id)
        """
        'ORDER BY tpl.bill_date DESC' is used to show the passbook data in bill_date descending order vise.
        """
        _get_transporter_passbook = _get_result_as_dict(
            _get_transporter_passbook_query + " ORDER BY tpl.bill_date DESC")
        if request.args.get('send', 0):
            _get_transporter_passbook_file = _get_result_as_dict(
                _get_transporter_passbook_file_query)
            _data = pd.DataFrame(_get_transporter_passbook_file)
            if len(_data):
                secure_name = secure_filename(
                    datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S'))
                file_name = secure_filename(
                    datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S') + ".csv")
                file_path = 'data/' + file_name
                _data.to_csv('data/' + file_name, index=False)
                file = open('data/' + file_name)
                if dealership_id:
                    _s3_file_prefix = 'Passbook/' + \
                                      str(transporter_id) + '/' + str(dealership_id)
                else:
                    _s3_file_prefix = 'Passbook/' + str(transporter_id)
                if request.args.get('download', 0):
                    if request.args.get('type') == 'pdf':
                        CSV_data = pd.read_csv(file_path)
                        CSV_data.to_html('data/' + secure_name + '.html')
                        html_path = 'data/' + secure_name + '.html'
                        options = {}
                        options.update({'header-html': 'template/header.html'})
                        with open(html_path) as f:
                            _pdf_name = "{}_transporter_passbook.pdf".format(
                                transporter_id)
                            pdfkit.from_file(
                                f, 'data/' + _pdf_name, options=options, configuration=_wkhtml_config)
                            message_bytes = open(
                                'data/' + _pdf_name, "rb").read()
                            file_bytes = base64.b64encode(message_bytes)
                            file = file_bytes.decode('ascii')

                            _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(
                                'transporters/' + _s3_file_prefix, _pdf_name,
                                transporter_docs_bucket, file)
                            f.close()
                            os.remove('data/' + file_name)
                            os.remove('data/' + secure_name + '.html')
                            if _upload_status:
                                return jsonify({'status': 'SUCCESS', 'data': _uploaded_file_url})
                            return jsonify({'status': 'ERROR', 'message': 'Unable to Download data'})
                    elif request.args.get('type') == 'csv':
                        _upload_status, _uploaded_file_url = _s3_file_upload('transporters/' + _s3_file_prefix,
                                                                             file_name,
                                                                             transporter_docs_bucket,
                                                                             file)
                        file.close()
                        os.remove('data/' + file_name)
                        if _upload_status:
                            return jsonify({'status': 'SUCCESS', 'data': _uploaded_file_url})
                        return jsonify({'status': 'ERROR', 'message': 'Unable to Download data'})
                    else:
                        return jsonify(
                            {'status': 'ERROR', 'message': 'Select the passbook document download format(pdf or csv).'})
                mail = {}
                email = request.args.get('mail')
                if not email:
                    return jsonify({"status": "ERROR", "message": "Please Enter Mail ID"})
                if len(email) > 0:
                    mail.update({'subject': 'petromoney passbook report',
                                 'body': """Dear Customer,\nGreetings from Petromoney!
                                 \nPlease find attached e-Statement of your passbook report as requested.
                                 \nThanks,\nTeam Petromoney""",
                                 'recipients': [email]

                                 })
                    file_to_attach = [file.name]
                    file_names = [file_name]
                    mail_status = _send_mail(mail, attachment=file_to_attach, file_name=file_names,
                                             file_type="text/csv")
                    file.close()
                    os.remove('data/' + file_name)
                    if mail_status.get_json().get('delivery'):
                        return jsonify({'status': 'SUCCESS', 'message': 'Mail sent successfully.'})
                return jsonify({'status': 'ERROR', 'message': "Unable to send mail."})
        return jsonify({'status': 'SUCCESS', 'data': _get_transporter_passbook})


def transporter_bill_upload(file, dealership_id, transporter_id):
    """
    if bill_images received, it uploads in s3 and uploaded file URL stored in transport_passbook_ledger
    """
    file_name = secure_filename(datetime.datetime.today().strftime(
        '%Y-%m-%d %H:%M:%S') + file.filename)
    if allowed_file(file_name):
        _s3_file_prefix = 'Bill/' + \
                          str(transporter_id) + '/' + str(dealership_id)
        _status, _uploaded_file_url = _s3_file_upload('transporters/' + _s3_file_prefix,
                                                      file_name,
                                                      transporter_docs_bucket,
                                                      file)
        if _status:
            return _uploaded_file_url
        else:
            abort(jsonify(
                {"status": "ERROR", "message": "File could not be uploaded to S3. Please try again."}))


@app.route('/api/dealership/<int:dealership_id>/<int:transporter_id>/repayment', methods=["POST"])
@jwt_required
def upload_repayment(dealership_id=None, transporter_id=None):
    """this API is used to pay the transporter fuel bill."""
    check_credit_limit = _get_result_as_dict(query_parser.get(
        'transporters', '_get_credit_limit').format(dealership_id, transporter_id))
    if check_credit_limit[0].get('used_limit') == 0:
        return jsonify(
            {"status": " ERROR", "message": "The used Limit is Rs.0 for this transporter, you are not allowed to pay"})
    data = format_date_in_data(encrypt_data(
        dict(request.form)), ['due_date', 'bill_date'])
    """ bill date is not get from UI, so it is generated in backend."""
    if not data.get('bill_date'):
        data.update(
            {'bill_date': datetime.datetime.now().strftime("%Y-%m-%d")})
    data.update({'dealership_id': dealership_id, 'transporter_id': transporter_id,
                 'created_by': get_jwt_identity(), 'amount': int(float(data.get('amount')))})
    _check_fields_in_request_data(REPAYMENT_FIELDS, data)
    _repayment_data = {key: data.get(key)
                       for key in REPAYMENT_FIELDS if data.get(key)}
    """ 
    if bill_images received, it uploads in s3 and uploaded file URL stored in transport_passbook_ledger 
    """
    if bool(request.files.get('bill_image')):
        _uploaded_file_url = transporter_bill_upload(
            request.files.get('bill_image'), dealership_id, transporter_id)
        _repayment_data.update({'doc_url': _uploaded_file_url})
    _query = mydb._gen_insert_query_exclude_cols('transport_passbook_ledger', sorted(
        set(mydb._get_columns('transport_passbook_ledger'))), _repayment_data)
    response = _execute_query(mydb.INSERT, _query, "Transaction success.", "Failed to add the record.")
    row_id = (response).get_json().get('row_id')
    if row_id:
        """It's used to generate a whatsapp and SMS notification data"""
        _whatsapp_and_sms_data = {}
        _get_mapped_dealership_data_query = query_parser.get(
            'transporters', '_get_transporter_dealership_credit_limits') + ' AND tdt.dealership_id = {1} '
        _get_mapped_dealership_data = _get_result_as_dict(
            _get_mapped_dealership_data_query.format(transporter_id, dealership_id))[0]
        _available_limit = (_get_mapped_dealership_data.get(
            'credit_limit') - _get_mapped_dealership_data.get('used_limit')) + _get_mapped_dealership_data.get(
            'excess_amount')
        _whatsapp_and_sms_data.update({"transporter_name": _get_mapped_dealership_data.get('transporter_name'),
                                       "dealership_name": _get_mapped_dealership_data.get('dealership_name'),
                                       "credit_amount": data.get('amount'),
                                       "available_limit": _available_limit})
        if data.get("is_active_sms") is True:
            transporter_sms_notification('repayment', _whatsapp_and_sms_data, [
                _get_mapped_dealership_data.get('transporter_mobile')])
        if data.get("is_active_whatsapp") is True:
            transporters_whatsapp_notification('repayment', _whatsapp_and_sms_data, [
                _get_mapped_dealership_data.get('transporter_mobile')])
        return jsonify({'status': 'SUCCESS', 'message': response.get_json()})

@app.route('/api/dealership/<int:dealership_id>/<int:transporter_id>/bill', methods=["POST"])
@jwt_required
def bill_upload(dealership_id=None, transporter_id=None):
    """ This API is used to Add the Transporter fuel bill."""
    check_credit_limit = _get_result_as_dict(query_parser.get(
        'transporters', '_get_credit_limit').format(dealership_id, transporter_id))
    if not check_credit_limit:
        return jsonify({"status": " ERROR", "message": "Please Add Credit Limit"})
    data = format_date_in_data(encrypt_data(
        dict(request.form)), ['due_date', 'bill_date'])
    """
    bill_date is fuel entry date. It's Stored in transport_passbook_ledger
    """
    cur_date = datetime.datetime.now()
    bill_date = datetime.datetime.strptime(data.get("bill_date"), "%Y-%m-%d")
    allowed_days = cur_date - bill_date
    if allowed_days.days < 3:
        ledger_data = {"bill_date": data.get("bill_date")}
        data.update({'dealership_id': dealership_id,
                     'transporter_id': transporter_id, 'created_by': get_jwt_identity()})
        query = mydb._gen_insert_query_exclude_cols('transport_vehicle_fuel_usage', sorted(
            set(mydb._get_columns('transport_vehicle_fuel_usage'))), data)
        response = _execute_query(mydb.INSERT, query, "Bill added succesfully", "Failed to add the record.")
        row_id = (response.get_json()).get('row_id')
        if row_id:
            """It's used to generate a whatsapp and SMS notification data"""
            _whatsapp_data = {}
            _whatsapp_data.update(data)
            _get_mapped_dealership_data_query = query_parser.get(
                'transporters', '_get_transporter_dealership_credit_limits') + ' AND tdt.dealership_id = {1} '
            _get_mapped_dealership_data = _get_result_as_dict(
                _get_mapped_dealership_data_query.format(transporter_id, dealership_id))
            if _get_mapped_dealership_data:
                _get_mapped_dealership_data[0].update({"dealership_name": _get_mapped_dealership_data[0].pop(
                    'name'), "transporter_name": _get_mapped_dealership_data[0].pop('transporter_name')})
                _whatsapp_data.update(_get_mapped_dealership_data[0])
            _available_limit = _get_mapped_dealership_data[0].get(
                'credit_limit') - _get_mapped_dealership_data[0].get('used_limit')
            if _available_limit <= 0:
                available_limit = 0
            else:
                available_limit = _available_limit
            _whatsapp_data.update(
                {"available_limit": available_limit, "credit_limit": _get_mapped_dealership_data[0].get(
                    'credit_limit'), "used_limit": _get_mapped_dealership_data[0].get('used_limit')})
            """
            eighty_percentage_amount is used to find 80% of used amount. After reaching 80%,
            WhatsApp and SMS messages will be sent to the particular Dealership.
            """
            eighty_percentage_amount = (80 / 100) * int(_get_mapped_dealership_data[0].get('credit_limit'))
            if _get_mapped_dealership_data[0].get('used_limit') >= eighty_percentage_amount:
                _get_main_dealer_mobile = _get_result_as_dict(query_parser.get(
                    'dealers', '_get_main_dealer').format(dealership_id))
                _mobile = [i.get('mobile') for i in _get_main_dealer_mobile]
                _whatsapp_data.update({"utilized_percentage": "80%"})
            #     transporters_whatsapp_notification(
            #         'limit_threshold_reaches', _whatsapp_data, sorted(set(_mobile)))
            #     transporter_sms_notification(
            #         'limit_threshold_reaches', _whatsapp_data, _mobile)
            # transporters_whatsapp_notification('completion_of_fuel_filling', _whatsapp_data, [
            #     _get_mapped_dealership_data[0].get('transporter_mobile')])
            # transporter_sms_notification('completion_of_fuel_filling', _whatsapp_data, [
            #     _get_mapped_dealership_data[0].get('transporter_mobile')])
        if data.get('bill_ref_no'):
            ledger_data.update({'bill_ref_no': data.get('bill_ref_no')})
        """ 
        if bill_images received, it uploads in s3 and uploaded file URL stored in transport_passbook_ledger 
        """
        if bool(request.files.get('bill_image')):
            _uploaded_file_url = transporter_bill_upload(
                request.files.get('bill_image'), dealership_id, transporter_id)
            ledger_data.update({'doc_url': _uploaded_file_url})
        if ledger_data:
            ledger_data.update({'created_by': get_jwt_identity()})
            column_list = sorted(
                set(mydb._get_columns('transport_passbook_ledger')))
            _query = mydb._gen_update_query(
                'transport_passbook_ledger', column_list, ledger_data)
            mydb.run_query(mydb.UPDATE, _query +
                           " WHERE debit_id={}".format(row_id))
            return jsonify({'status': 'SUCCESS', 'message': response.get_json()})
    else:
        return jsonify({'status': 'ERROR', 'message': "Do not upload bills older than three(3) days."})


@app.route('/api/dealership/<int:dealership_id>/<int:transporter_id>/bill/<int:id>', methods=["POST"])
@jwt_required
def bill_edit(dealership_id=None, transporter_id=None, id=None):
    """ This API is used to update the Transporter fuel bill."""
    data = format_date_in_data(encrypt_data(
        dict(request.form)), ['due_date', 'bill_date'])
    cur_date = datetime.date.today().strftime("%Y-%m-%d")
    if cur_date == data.get("bill_date"):
        _check_amount = \
            _get_result_as_dict(query_parser.get('transporters', '_get_transporter_bill_amount_check').format(id))[0]
        if _check_amount.get('amount_due') == _check_amount.get('amount'):
            data.update({'last_modified_by': get_jwt_identity(), 'amount': data.get("amount_due")})
            ledger_columns = mydb._get_columns('transport_passbook_ledger')
            fuel_usage_columns = mydb._get_columns('transport_vehicle_fuel_usage')
            _query = mydb._gen_update_query('transport_passbook_ledger', ledger_columns, data)
            _execute_query(mydb.UPDATE, _query + " WHERE debit_id={}".format(id))
            _query = mydb._gen_update_query('transport_vehicle_fuel_usage', fuel_usage_columns, data)
            return _execute_query(mydb.UPDATE, _query + " WHERE id={}".format(id), "bill updated successfully",
                                  "unable to update the records")
        else:
            return jsonify({'status': 'ERROR', 'message': 'Editing denied as the bill has been paid.'})
    else:
        return jsonify({'status': 'ERROR', 'message': 'Editing denied for older bills.'})


@app.route('/api/transporter/<int:transporter_id>/vehicle/<vehicle_no>/bill', methods=['GET'])
@jwt_required
def _get_transporters_bill_details(transporter_id=None, vehicle_no=None):
    """ This API is used to get fuel bill details using vehicle number."""
    if transporter_id:
        if vehicle_no:
            query = query_parser.get('transporters', '_get_bill_details_by_vehicle').format(vehicle_no)
            result = mydb.run_query(mydb.SELECT, query)
            return jsonify({"status": "SUCCESS", "data": result})


def transporters_whatsapp_notification(status, whatsapp_data, mobile):
    """It's used to generate a WhatsApp message a payloads and call WhatsApp 3rd party API."""
    details = _get_result_as_dict(query_parser.get(
        'whatsapp_notification', '_get_template_id_and_roles_from_status').format(status))
    if details:
        details = details[0]
        payload = {"template": {
            "body": [],
            "langCode": "en",
            "templateId": details.get('template_name')
        }}
        for key in details.get('payload_keys').split(','):
            payload['template']['body'].append(
                {"type": "text", "text": whatsapp_data.get(key)})
        whatsapp_add_optin(mobile)
        for i in set(mobile):
            _push_to_whatsapp(to=i, type='template', message_content=payload)


def transporter_sms_notification(status, data, mobile):
    """ this function is used to generate the SMS payload and call the SMS 3rd party API."""
    details = _get_result_as_dict(query_parser.get(
        'sms', '_get_template_id_using_name').format(status))[0]
    payload_keys = details.get('payload_key').split(',')
    payload_name = details.get('payload_name').split(',')
    headers = {
        'authkey': SMS_API_AUTH_KEY,
        'content-type': "application/JSON"
    }
    for _mobile in mobile:
        payload = {
            "flow_id": details.get('template_id'),
            "mobiles": "+91" + str(_mobile)
        }
        for key in payload_keys:
            index = payload_keys.index(key)
            payload.update({payload_name[index]: data.get(key)})
        conn = http.client.HTTPSConnection("api.msg91.com")
        conn.request("POST", "/api/v5/flow/", json.dumps(payload), headers)
        response = json.loads(conn.getresponse().read().decode('utf-8'))
        return response


@app.route('/api/transporter/mapped/dealership', methods=['GET'])
@jwt_required
def get_transporter_id():
    """" This API is used to get the transporter id and also get the transporter mapped dealerships """
    _user_data = mydb.run_query(mydb.SELECT, query_parser.get(
        'users', '_get_user_details_by_id').format(get_jwt_identity()))
    if _user_data[0].get('role_id') == 14:
        _transporter_data = mydb.run_query(mydb.SELECT, query_parser.get(
            'transporters', '_get_transporter_by_mobile').format(_user_data[0].get('mobile')))
        if _transporter_data:
            _get_mapped_dealership_id = _get_result_as_dict(query_parser.get(
                'transporters', '_get_transporter_dealership_credit_limits').format(
                _transporter_data[0].get('transporter_id')))
            if _get_mapped_dealership_id:
                return jsonify({'status': 'SUCCESS', 'data': _get_mapped_dealership_id})
            else:
                return jsonify({'status': 'SUCCESS', 'data': _transporter_data})
        return jsonify({'status': 'SUCCESS', 'message': 'No Transporter Found'})
    return jsonify({"status": "ERROR", "message": "Unauthorized access. "+_support_message})


@app.route('/api/sms/send', methods=['POST'])
@jwt_required
def send_sms():
    """
    this API is used in Lambda Handler, and
    it's used to send the SMS Due notification.
    """
    data = request.get_json()
    return transporter_sms_notification(data.pop('status'), data, [data.get('mobile')])


@app.route('/api/<int:dealership_id>/transporter/<int:transporter_id>/credit/limit', methods=["POST"])
@jwt_required
def credit_limit(dealership_id=None, transporter_id=None):
    """
    This API is used to update and reload the transporter credit limit after verifying the OTP verification
    """
    data = request.get_json()
    _get_dealership_mapped_transporter_query = query_parser.get(
        'transporters', '_get_mapped_dealership_and_transportes')
    _get_dealership_mapped_transporter_query = _get_dealership_mapped_transporter_query + \
                                               ' AND dtm.transporter_id = {1} '
    check_credit_limit = _get_result_as_dict(
        _get_dealership_mapped_transporter_query.format(dealership_id, transporter_id))
    check_credit_limit[0].update({'amount': data.get('credit_limit')})
    if check_credit_limit[0].get('credit_limit'):
        template_name = 'modify_the_limit'
        data.update({'last_modified_by': get_jwt_identity()})
    else:
        template_name = 'set_a_limit'
        data.update({'created_by': get_jwt_identity(),
                     'last_modified_by': get_jwt_identity()})
    _query = query_parser.get('users', '_get_user_details_by_id')
    if data.get("credit_limit"):
        data.update({'dealership_id': dealership_id,
                     'transporter_id': transporter_id})
        _col_list = mydb._get_columns('transport_credit_limits')
        _query = mydb._gen_upsert_query(
            'transport_credit_limits', sorted(set(_col_list)), data)
        _transporter_data = _get_result_as_dict(query_parser.get(
            'transporters', '_get_all_transporters') + ' WHERE transporter_id = {0}'.format(transporter_id))
        mobile = [_transporter_data[0].get('mobile')]
        transporter_sms_notification(
            template_name, check_credit_limit[0], mobile)
        transporters_whatsapp_notification(
            template_name, whatsapp_data=check_credit_limit[0], mobile=mobile)
        return _execute_query(mydb.UPDATE, _query)
    return jsonify({"status": "ERROR", "message": "Please, Enter the Credit Limit Amount"})


@app.route('/api/transporters/search', methods=['GET'])
@jwt_required
def transporter_search():
    """ This API is used to search transporter using mobile numbers and Names """
    name = request.args.get('name')
    mobile = request.args.get('mobile')
    _query = query_parser.get('transporters', '_get_all_transporters')
    _get_transport = _get_result_as_dict(
        _query + " WHERE (t.name LIKE '%{0}%' OR t.mobile LIKE '%{1}%')".format(name, mobile))
    if not _get_transport:
        return jsonify({'status': 'SUCCESS', 'message': 'No Transporter Found'})
    return jsonify({'status': 'SUCCESS', 'data': _get_transport})


@app.route('/api/transporter/due/report', methods=['POST'])
@jwt_required
def _due_report():
    _due = _get_result_as_dict(query_parser.get('transporters', '_get_transporter_due_report_for_remainder'))
    _over_due = _get_result_as_dict(query_parser.get('transporters', '_get_transporter_due_report_for_remainder'))
    return jsonify({"status": "SUCCESS", "due": _due, "over_due": _over_due})


@app.route('/api/<int:dealership_id>/<int:transporter_id>/due/report', methods=['GET'])
@jwt_required
def due_and_overdue_report(dealership_id, transporter_id):
    """This API used to get the transporter due and over due report."""
    due_query = query_parser.get('transporters', '_get_transporter_due_report')
    overdue_query = query_parser.get('transporters', '_get_transporter_overdue_report')
    due = _get_result_as_dict(due_query.format(dealership_id, transporter_id))
    overdue = _get_result_as_dict(overdue_query.format(dealership_id, transporter_id))
    return jsonify({'status': "SUCCESS", "due": due, "over_due": overdue})


@app.route('/api/transporters', methods=["POST"])
@app.route('/api/transporters/<int:transporter_id>', methods=["POST", "DELETE"])
@jwt_required
def _transporters(transporter_id=None):
    if request.method == 'POST':
        data = format_date_in_data(encrypt_data(dict(request.form)), ['doi'])
        if _check_duplicates("t_transports", data, applicant_id=transporter_id):
            return jsonify({"status": "ERROR", "message": "Duplicate KYC records (Aadhar/PAN/Mobile)"})
        data.update({"last_modified_by": get_jwt_identity()})
        t_owner_id = data.get('t_owner_id')
        _col_list = mydb._get_columns('t_transports')
        if transporter_id is None:
            _query = mydb._gen_insert_query_exclude_cols('t_transports', _col_list, data)
            affected_rows, transporter_id = mydb.run_query(mydb.INSERT, _query, row_insert_id=True)
        if bool(request.files):
            _status_, result = _upload_kyc_docs(request.files, origin_id=transporter_id, type='transport')
            if _status_:
                data.update(result)
        _query = mydb._gen_update_query("t_transports", _col_list, data)
        mydb.run_query(mydb.UPDATE, _query + " WHERE transporter_id={}".format(transporter_id))
        return jsonify({'status': 'SUCCESS', 'message': 'Transport added successfully'})
    if request.method == 'DELETE':
        data = request.get_json()
        query = query_parser.get('transporters', '_remove_transporters_attachment').format(list(data)[0],
                                                                                           transporter_id)
        mydb.run_query(mydb.DELETE, query)
        return jsonify({'status': 'SUCCESS', 'message': 'Attachment removed succesfully'})


def _map_user_transport_owner(_map_data):
    _query = mydb._gen_insert_query('t_user_transport_owners_map', _map_data)
    return mydb.run_query(mydb.INSERT, _query)


@app.route('/api/transporters/<int:transporter_id>/vehicles', methods=["GET", "POST"])
@app.route('/api/transporters/<int:transporter_id>/vehicles/<int:vehicle_id>', methods=["POST", "DELETE"])
@jwt_required
def _get_transporters_vehicles(transporter_id=None, vehicle_id=None):
    if transporter_id:
        if request.method == 'GET':
            return _get_result(query_parser.get('transporters', '_get_vehicles_info').format(transporter_id))
        elif request.method == 'POST':
            data = request.get_json()
            data.update({"transporter_id": transporter_id})
            if data.get('tt_no'):
                vehicle_details = _get_vehicle_details(data.get('tt_no')).get_json()
                if vehicle_details.get('status') == 'ERROR':
                    return vehicle_details
            if vehicle_id:
                col_list = mydb._get_columns('t_transporter_vehicles')
                query = mydb._gen_update_query('t_transporter_vehicles', col_list, data)
                return _execute_query(mydb.UPDATE, query + " WHERE id = {0}".format(vehicle_id))
            else:
                query = mydb._gen_insert_query('t_transporter_vehicles', data)
                return _execute_query(mydb.INSERT, query)
        elif request.method == 'DELETE':
            query = "DELETE FROM t_transporter_vehicles WHERE id = {0} AND transporter_id = {1}".format(vehicle_id,
                                                                                                        transporter_id)
            return _execute_query(mydb.DELETE, query)
    else:
        return jsonify(error_parser.get('invalid', '_id_details_missing')), 200


@app.route('/api/transporter/<int:transporter_id>/vehicle/<int:vehicle_id>/docs', methods=['GET', 'POST'])
@app.route('/api/transporter/<int:transporter_id>/vehicle/<int:vehicle_id>/docs/<int:id>', methods=['DELETE'])
@jwt_required
def _get_transporters_vehicles_documents(transporter_id=None, vehicle_id=None, id=None):
    if request.method == 'POST':
        data = dict(request.form)
        data.update({"last_modified_by": get_jwt_identity()})
        data.update({"transporter_id": transporter_id, "vehicle_id": vehicle_id})
        if request.files:
            try:
                for file in request.files:
                    _status, file_path = _vehicle_file_upload(request.files.getlist(file), transporter_id, vehicle_id,
                                                              data.get('document_name'), doc_id=data.get('document_id'))
                    data.update({'file_path': file_path})
                    col_list = mydb._get_columns('t_transporter_vehicle_document_checklist')
                    query = mydb._gen_insert_query_exclude_cols("t_transporter_vehicle_document_checklist", col_list,
                                                                data)
                    insert_response = _is_rows_affected(query)
                    return jsonify(
                        {"status": "SUCCESS", "message": "File uploaded successfully", "file_url": file_path})
            except Exception as e:
                logger.debug('Error: {}'.format(e))
                return jsonify({"status": "ERROR",
                                "message": "Details could not be updated as file can't be uploaded. "
                                           "Please email the document to sales@petromoney.co.in"})
    elif request.method == 'DELETE':
        remove_query = query_parser.get('transporters', '_remove_vehicle_docs').format(0, id)
        return _execute_query(mydb.DELETE, remove_query)
    elif request.method == 'GET':
        return _get_result(query_parser.get('transporters', '_get_vehicle_docs').format(vehicle_id))


@app.route('/api/vehicle/<int:vehicle_id>/loan', methods=['POST', 'GET'])
@app.route('/api/vehicle/<int:vehicle_id>/loan/<int:loan_id>', methods=['POST', 'DELETE'])
@jwt_required
def _transporter_vehicle_loan(vehicle_id=None, loan_id=None):
    if request.method == 'POST':
        data = request.get_json()
        data.update({"last_modified_by": get_jwt_identity()})
        data.update({"vehicle_id": vehicle_id})
        _col_list = ['vehicle_id', 'credit_head_id', 'loan_amount', 'remarks', 'last_modified_by']
        if loan_id:
            query = mydb._gen_update_query("t_transporter_loans", _col_list, data)
            return _is_rows_affected(query + " WHERE id={}".format(loan_id))
        else:
            query = mydb._gen_insert_query("t_transporter_loans", data)
            return _is_rows_affected(query)
    elif request.method == "DELETE":
        if loan_id:
            query = query_parser.get("transporters", "_remove_vehicle_loans").format(loan_id)
            return _execute_query(mydb.DELETE, query)
    elif request.method == "GET":
        return _get_result(query_parser.get('transporters', '_get_vehicle_loans').format(vehicle_id))


@app.route('/api/vehicle/loans', methods=['GET'])
@jwt_required
def _vehicle_list_with_loans():
    if request.method == 'GET':
        return _get_result(query_parser.get('transporters', '_get_vehicle_details_with_loan'))


@app.route('/api/vehicle/<int:vehicle_id>/service/<int:credit_head_id>/tracker/<int:loan_id>', methods=['GET', 'POST'])
@jwt_required
def _vehicle_loan_tracker(vehicle_id=None, credit_head_id=None, loan_id=None):
    if request.method == 'GET':
        data = {}
        _service_steps = mydb.run_query(mydb.SELECT,
                                        query_parser.get('transporters', '_get_service_steps').format(credit_head_id))
        _service_tracking_details = mydb.run_query(mydb.SELECT, query_parser.get('transporters',
                                                                                 '_get_vehicle_service_status').format(
            vehicle_id, credit_head_id, loan_id))
        data.update(
            {"vehicle_id": vehicle_id, "credit_head_id": credit_head_id, "loan_id": loan_id, "steps": _service_steps,
             "tracking_details": _service_tracking_details})
        return jsonify({"status": "SUCCESS", "data": data})
    elif request.method == 'POST':
        data = request.get_json()
        data.update({"vehicle_id": vehicle_id, "option_id": credit_head_id, "loan_id": loan_id})
        _col_list = mydb._get_columns('vehicle_loan_tracker')
        _query = mydb._gen_upsert_query('vehicle_loan_tracker', _col_list, data)
        return _execute_query(mydb.INSERT, _query)


@app.route('/api/vehicle/<int:vehicle_id>/service/<int:loan_id>', methods=['POST'])
@jwt_required
def _vehicle_service_state(vehicle_id=None, loan_id=None):
    if request.method == 'POST':
        data = request.get_json()
        _status_info = mydb.run_query(mydb.SELECT,
                                      query_parser.get('transporters', '_get_service_status_info')
                                      .format(vehicle_id, loan_id, data.get("option_id"), data.get("status_id")))
        if _status_info:
            _update_service = mydb.run_query(mydb.UPDATE,
                                             "UPDATE vehicle_loan_tracker SET details='{0}', last_modified_by='{1}' "
                                             "WHERE vehicle_id='{2}' AND loan_id='{3}' AND options_id='{4}' AND status_id='{5}'".format(
                                                 data.get("details"), data.get('user_id', 0), vehicle_id, loan_id,
                                                 data.get("option_id"), data.get("status_id")))
        else:
            _add_new_service = mydb.run_query(mydb.INSERT,
                                              "INSERT INTO vehicle_loan_tracker(vehicle_id, loan_id, option_id, "
                                              "status_id, details, last_modified_by) values('{0}', '{1}', '{2}', '{3}', '{4}', '{5}')".format(
                                                  vehicle_id, loan_id, data.get("option_id"), data.get("status_id"),
                                                  data.get("details"), data.get('user_id', 0)))
        return jsonify({"status": "SUCCESS", "message": "Service status updated"})


@app.route('/api/document/sign', methods=['POST'])
@app.route('/api/document/sign/<document_id>', methods=['GET', 'DELETE'])
@jwt_required
def _get_document_to_sign(document_id=None):
    if request.method == 'POST':
        data = convert_keys_to_lowercase(request.get_json())
        """This is due to the case where in mobile it comes as 'dealershipId' and from mdm it is 'dealership_id'"""
        dealership_id = data.get("dealership_id")
        loan_id = data.get("loanid")
        _dealers = data.get('dealer')
        _coapplicants = data.get('coapplicants', [])
        _fintech = json.loads(os.getenv('GREEN_MALABAR_FINTECH'))
        _guarantor = data.get('guarantor', [])
        dealership_details = mydb.run_query(mydb.SELECT, query_parser.get('dealership',
                                                                          '_get_all_dealerships') + " WHERE md.id = {}".format(
            dealership_id))
        if dealership_details:
            application_name = dealership_details[0].get('application_name')
        if data.get('type') == 'sanction':
            document_name = "SanctionLetter"
            template_id = "CqL3GGh" if os.getenv("ENVIRONMENT") == "UAT" else "EFS9I65"
            payload_template = 'SanctionLetterSigning_payload.json'
            stampSeries = None
        elif data.get('type') == 'agreement':
            document_name = "LoanAgreementLetter"
            template_id = "eNLb5WK" if os.getenv("ENVIRONMENT") == "UAT" else "I5U1ZWC"
            payload_template = 'AgreementSigning_payload.json'
            stampSeries = "01"
        elif data.get('type') == 'application':
            document_name = ""
            template_id = ""
            payload_template = ''
            stampSeries = "None"
        return _e_sign_document(
            loan_id, dealership_id,
            {"json_file_name": application_name + document_name, "templateId": template_id,
             'Date': datetime.date.today().strftime("%d-%m-%Y")},
            payload_template, stampSeries, data.get('type'), _dealers, _coapplicants, _guarantor, _fintech,
            application_name
        )
    elif request.method == 'GET':
        return _e_sign_document(document_id=document_id)


def _e_sign_document(loan_id=None, dealership_id=None, file_attributes=None, payload_template=None, stampSeries=None,
                     type=None, _dealers=None, _coapplicants=None, _guarantor=None, _fintech=None,
                     application_name=None,
                     document_id=None):
    auth_token = LEEGALITY_AUTH_TOKEN
    if request.method == 'POST':
        invitees_list = []
        try:
            if not _dealers:
                logger.error("Dealer not found")
                return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_incomplete_details')})

            file_attributes.update({'residence_address': _dealers[0].get('address', ""),
                                    'dealer_first_name': _dealers[0].get('first_name'),
                                    'dealer_last_name': _dealers[0].get('last_name')})
            file_attributes.update(_dict_to_string("coborrower", _coapplicants))
            file_attributes.update(_dict_to_string("guarantor", _guarantor))
            co_borrowers_names = file_attributes.get('coborrower_names')+file_attributes.get('guarantor_names')
            file_attributes.update({'co_borrowers_names':co_borrowers_names.replace(',','/'),'current_date':datetime.datetime.now(timezone("Asia/Kolkata")).strftime('%d-%m-%Y')})
            dealership_details = mydb.run_query(mydb.SELECT,
                                                query_parser.get('dealership', '_get_dealership_by_id').format(
                                                    dealership_id))
            file_attributes.update(dealership_details[0])

            loan_data = mydb.run_query(mydb.SELECT,
                                       query_parser.get('dealership', '_get_loan_details_by_id').format(loan_id,
                                                                                                        dealership_id))
            file_attributes.update(loan_data[0])
            if loan_data[0].get("amount_approved") >= 0:
                file_attributes.update({"amount_approved_words": num2words(
                    decimal.Decimal(loan_data[0].get("amount_approved"))) + " Rupees Only"})
            if type == 'application':
                _fintech = []
            for i in _dealers + _coapplicants + _guarantor + _fintech:
                invitees_list.append({
                    "name": i.get("first_name") + ' ' + i.get("last_name"),
                    "phone": i.get("mobile", ""),
                    "email": i.get("email", ""),
                    "emailNotification": True,
                    "phoneNotification": True,
                    "webhook": {
                        "success": LEEGALITY_WEB_HOOK,
                        "failure": LEEGALITY_WEB_HOOK,
                        "version": 2.1
                    }
                })
                signatures = i.get("signatures", [])
                if len(signatures) == 2:
                    invitees_list[len(invitees_list) - 1].update({"signatures": [
                        {"type": "AADHAAR", "config": {"authTypes": ["OTP"]}}, {"type": "VIRTUAL_SIGN"}]})
                elif len(signatures) == 0 or len(signatures) == 1 and "AADHAAR" in signatures:
                    invitees_list[len(invitees_list) - 1].update(
                        {"signatures": [{"type": "AADHAAR", "config": {"authTypes": ["OTP"]}}]})
        except Exception as e:
            logger.debug("Exception in document sign because: {}".format(e))
            return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_incomplete_details')})

        template_filepath = os.path.join(os.getcwd(), "template", payload_template)
        target_folder = os.path.join(os.getcwd(), "template")
        target_filepath = os.path.join(os.getcwd(), "template", 'temp.json')

        _url = LEEGALITY_URL + "/api/v2.1/sign/request"
        _headers = {
            'X-Auth-Token': auth_token,
            'Content-Type': 'application/json'
        }
        try:
            if type in ["application", "sanction"]:
                if type == "application":
                    _file_url = _generate_application_letter(dealership_id, loan_id).get_json().get('file')
                else:
                    _file_url = _generate_sanction_letter_base64(dealership_id, loan_id).get_json().get('file')
                payload = {
                    "file": {
                        "name": "{}_Application".format(application_name),
                        "fileUrl": _file_url,
                    },
                    "invitees": [],
                    "irn": "",
                    "requestSignOrder": False
                }
            else:
                _find_and_replace(template_filepath, target_folder, 'temp.json', file_attributes)
                with open(target_filepath) as template_file:
                    payload = json.loads(template_file.read(), strict=False)
                logger.debug("Closing files")
                template_file.close()
                if stampSeries:
                    payload.update({"stampSeries": stampSeries})
            payload.update({"invitees": invitees_list})
            payload.update({"irn": uuid.uuid1().int})

            try:
                response = req.post(_url, headers=_headers, data=json.dumps(
                    payload))  # json.dumps is mandatory to convert single quote json into double quote JSON string
                response_json = json.loads(response.text)
                res_document_id = response_json.get("data").get("documentId")
                _query = mydb._gen_insert_query('e_sign_stamp_history', {
                    "dealership_id": dealership_id,
                    "document_id": res_document_id,
                    "document_type": type,
                    "loan_id": loan_id,
                    "invitees_remain": len(invitees_list),
                    "tot_invitees": len(invitees_list)
                })
                if response_json.get("status"):
                    _result = _execute_query(mydb.INSERT, _query)
                    return jsonify({"status": "SUCCESS", "message": "Document signing process has been initiated",
                                    "data": response_json.get("data")})
                else:
                    return jsonify({"status": "ERROR", "message": response_json.get("messages")[0].get("message"),
                                    "data": response_json.get("data")})

            except req.exceptions.Timeout:
                # Maybe set up for a retry, or continue in a retry loop
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_timeout')})
            except req.exceptions.TooManyRedirects:
                # Tell the user their URL was bad and try a different one
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_too_many_redirects')})
            except req.exceptions.RequestException:
                # catastrophic error. bail.
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_request_exception')})
        except IOError as err:
            logger.debug("Workflow file not found in path")
            return jsonify({"status": "ERROR", "message": "Workflow template file not found in the template path"})

    elif request.method == 'GET':
        if auth_token:
            try:
                _url = LEEGALITY_URL + "/api/v2.1/sign/request"
                _headers = {
                    'X-Auth-Token': auth_token,
                    'Content-Type': 'application/json'
                }
                data = {
                    "document_id": document_id
                }
                response = req.get(_url, headers=_headers, data=data)
                return jsonify(
                    {"status": "SUCCESS", "messsage": "e-sign request successful", "data": json.loads(response.text)})

            except req.exceptions.Timeout:
                # Maybe set up for a retry, or continue in a retry loop
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_timeout')})
            except req.exceptions.TooManyRedirects:
                # Tell the user their URL was bad and try a different one
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_too_many_redirects')})
            except req.exceptions.RequestException:
                # catastrophic error. bail.
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_request_exception')})
        else:
            return jsonify({"status": "ERROR", "message": "Auth token is empty"})
    elif request.method == 'DELETE':
        if auth_token:
            try:
                _url = LEEGALITY_URL + "/api/v2.1/sign/request"
                _headers = {
                    'X-Auth-Token': auth_token,
                    'Content-Type': 'application/json'
                }
                data = {
                    "document_id": document_id
                }
                response_text = req.delete(_url, headers=_headers, data=data)
                return jsonify({"status": "SUCCESS", "message": json.loads(response_text.text)})

            except req.exceptions.Timeout:
                # Maybe set up for a retry, or continue in a retry loop
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_timeout')})
            except req.exceptions.TooManyRedirects:
                # Tell the user their URL was bad and try a different one
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_too_many_redirects')})
            except req.exceptions.RequestException:
                # catastrophic error. bail.
                return jsonify({"status": "SUCCESS", "message": error_parser.get('invalid', '_request_exception')})
        else:
            return jsonify({"status": "ERROR", "message": "Auth token is empty"})


@app.route('/api/document/reactivate/<document_id>', methods=['GET'])
@app.route('/api/document/reactivate/<document_id>/<int:expiry_days>', methods=['GET'])
@jwt_required
def _reactivate_document(document_id=None, expiry_days=10):
    if document_id:
        try:
            response = req.post(LEEGALITY_URL + "/api/v3.0/sign/request/reactivate",
                                params={'documentId': document_id, "expiryDays": expiry_days},
                                headers={'X-Auth-Token': LEEGALITY_AUTH_TOKEN})
            return jsonify({"status": "SUCCESS", "message": "Sign request activation successful",
                            "data": json.loads(response.text)})
        except req.exceptions.Timeout:
            return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_timeout')})
        except req.exceptions.TooManyRedirects:
            return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_too_many_redirects')})
        except req.exceptions.RequestException:
            return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_request_exception')})
    return jsonify({"status": "ERROR", "message": "No document found. Check if the document id is correct."})


@app.route('/api/document/resend', methods=['POST'])
@jwt_required
def _resend_document():
    data = request.get_json()
    try:
        response = req.post(LEEGALITY_URL + "/api/v3.0/sign/request/resend",
                            params={'signUrls': data.get("sign_url")},
                            headers={'X-Auth-Token': LEEGALITY_AUTH_TOKEN})
        return jsonify(
            {"status": "SUCCESS", "message": "Notification sent successfully.", "data": json.loads(response.text)})
    except req.exceptions.Timeout:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_timeout')})
    except req.exceptions.TooManyRedirects:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_too_many_redirects')})
    except req.exceptions.RequestException:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_request_exception')})


@app.route('/api/document/history/<int:loan_id>', methods=['GET'])
@jwt_required
def _get_document_by_loan(loan_id=None):
    if loan_id:
        _query = query_parser.get("e_sign_stamp", "_get_documents_by_loan_id").format(loan_id)
        if request.args.get('document_type'):
            _query = query_parser.get("e_sign_stamp", "_get_documents_by_document_type").format(loan_id,
                                                                                                request.args.get(
                                                                                                    'document_type'))
        _result = mydb.run_query(mydb.SELECT, _query)
        return jsonify({"status": "SUCCESS", "data": _result})


@app.route('/api/document/trail/<document_id>', methods=['GET'])
@jwt_required
def _get_audit_trail(document_id=None):
    if document_id:
        response = req.get(LEEGALITY_URL + "/api/auditTrail",
                           params={'documentId': document_id, 'auditTrail': True},
                           headers={'X-Auth-Token': LEEGALITY_AUTH_TOKEN})
        return jsonify({"status": "SUCCESS", "message": "Audit trail data", "data": response.json()})
    return jsonify({"status": "ERROR", "msg": "No document found. Check if the document id is correct."})


@app.route('/api/dealership/<int:dealership_id>/document/<document_id>', methods=['GET'])
@jwt_required
def _get_document_details(document_id=None, dealership_id=None):
    e_sign_data = mydb.run_query(mydb.SELECT,
                                 query_parser.get('e_sign_stamp', '_get_sign_details_by_document_id').format(
                                     document_id))
    if e_sign_data and e_sign_data[0].get('request'):
        _document_details = json.loads(e_sign_data[0].get('request'))
        if _document_details.get('status'):
            _document_details.update({"file": e_sign_data[0].get("file")})
            return jsonify({'data': {'data': _document_details, "status": "SUCCESS"}, 'status': 'SUCCESS'})
    return _get_leegality_details(document_id, dealership_id)


def _get_leegality_details(document_id=None, dealership_id=None):
    try:
        response = req.get(LEEGALITY_URL + "/api/v3.0/document/details",
                           params={'documentId': document_id, 'auditTrail': True},
                           headers={'X-Auth-Token': LEEGALITY_AUTH_TOKEN})
        _response = response.json()
        if not _response.get('data'):
            logger.debug("no document details found for the document id {}".format(document_id))
            return jsonify({"status": "ERROR", "message": "No document details found"})
        file_message = _response.get('data').pop('file')
        _pdf_name = '{}_document.pdf'.format(document_id)
        _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(str(dealership_id),
                                                                                  _pdf_name,
                                                                                  dealership_docs_bucket,
                                                                                  file_message)
        if _upload_status:
            data = {'document_url': _uploaded_file_url, 'request': json.dumps(_response.get('data'))}
            result = mydb.run_query(mydb.UPDATE, mydb._gen_update_query(table_name='e_sign_stamp_history',
                                                                        columns=['document_url', 'request'],
                                                                        data=data) + "WHERE document_id = '{}'".format(
                document_id))
            e_sign_data = mydb.run_query(mydb.SELECT,
                                         query_parser.get('e_sign_stamp', '_get_sign_details_by_document_id').format(
                                             document_id))
            return jsonify({"status": "SUCCESS", "data": e_sign_data})
    except req.exceptions.Timeout:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_timeout')})
    except req.exceptions.TooManyRedirects:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_too_many_redirects')})
    except req.exceptions.RequestException:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_request_exception')})
    except json.decoder.JSONDecodeError:
        error_msg = "Couldn't get valid response from leegality \n URL -> {} \n Parameter -> {} response -> {}".format(
            LEEGALITY_URL + "/api/v3.0/document/details", {'documentId': document_id, 'auditTrail': True},
            response.text)
        logger.error(error_msg)
        alert_chat_app(os.getenv('ACTIVE_CHAT_APP_TO_NOTIFY'), error_msg)
        return jsonify({'status': "ERROR", 'message': "Couldn't handle the request please try again."})


@app.route('/api/leegality/report', methods=['POST'])
def _leegality_webhook():
    try:
        data = request.get_json()
        e_sign_details_by_document_id = mydb.run_query(mydb.SELECT,
                                                       query_parser.get('e_sign_stamp',
                                                                        '_get_sign_details_by_document_id').format(
                                                           data.get('documentId')))
        leegality_details = _get_leegality_details(document_id=data.get('documentId'),
                                                   dealership_id=e_sign_details_by_document_id[0].get(
                                                       'dealership_id')).get_json()
        if leegality_details.get('status') != 'SUCCESS':
            return leegality_details
        e_sign_data = leegality_details.get('data')[0]
        if len(e_sign_data) == 0 or not data.get('files'):
            return jsonify({"status": "ERROR", "message": "Provided document_id doesnt exist"})
        dealership_id = e_sign_data.get('dealership_id')
        _type = e_sign_data.get('document_type')
        loan_id = e_sign_data.get('loan_id')
        _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(
            str(dealership_id) + "/{0}/{1}".format(loan_id, _type),
            "{}.pdf".format(_type),
            dealership_docs_bucket,
            data.get('files')[0])
        if _upload_status:
            logger.debug("Uploaded document to path %s", _uploaded_file_url)
        else:
            logger.debug("Upload Error: Document could not be uploaded to S3. Please try again.")
            return jsonify({"status": "ERROR",
                            "message": "Document generated, but upload to S3 failed."+_support_message})
        data.update({'request': json.dumps(data), 'document_url': _uploaded_file_url})
        _query = mydb._gen_update_query('e_sign_stamp_history', ["mac", "signer", "request", "document_url", "irn"],
                                        data) + ",invitees_remain=invitees_remain-1 WHERE {0}='{1}'".format(
            "document_id", data.get("documentId"))
        if e_sign_data.get('invitees_remain') == 1:
            _doc_data = {'dealership_id': dealership_id, 'document_id': _type.replace('agreement', 'loan-agreement'),
                         'file_path': _uploaded_file_url, 'dealer_id': 0, 'status': 1}
            _doc_data = _get_id_by_key(_doc_data, 'document_id', 'm_document_checklist', 'doc_name')
            _execute_query(mydb.INSERT, mydb._gen_insert_query_exclude_cols('t_dealership_document_checklist',
                                                                            mydb._get_columns(
                                                                                't_dealership_document_checklist'),
                                                                            _doc_data))
        return _execute_query(mydb.UPDATE, _query)
    except Exception as e:
        logger.debug("Invalid input error: {}".format(e))
        return jsonify({"status": "ERROR", "message": "Invalid input"})


@app.route('/api/document/completed', methods=['GET'])
@jwt_required
def _get_document_completed():
    try:
        _url = LEEGALITY_URL + "/api/v3.0/document/completed"
        _headers = {
            'X-Auth-Token': os.getenv('LEEGALITY_AUTH_TOKEN'),
            'Content-Type': 'application/json'
        }
        response = req.get(_url, headers=_headers)
        return jsonify({"status": "SUCCESS", "message": json.loads(response.text)})
    except req.exceptions.Timeout:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_timeout')})
    except req.exceptions.TooManyRedirects:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_too_many_redirects')})
    except req.exceptions.RequestException:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_request_exception')})


@app.route('/api/document/remove/invitation', methods=['POST'])
@jwt_required
def _delete_document_invite():
    try:
        data = request.get_json()
        _url = LEEGALITY_URL + "/api/v3.0/sign/request/invitation"
        _headers = {
            'X-Auth-Token': os.getenv('LEEGALITY_AUTH_TOKEN'),
            'Content-Type': 'application/json'
        }
        _check_fields_in_request_data(['signUrl', 'document_id'], data)
        document_id = data.get('document_id')
        response = req.delete(_url, headers=_headers, params={'signUrl': data.get('signUrl')})
        _response = response.json()
        if _response and _response.get('status'):
            _request_data = _get_result_as_dict(
                "select request from e_sign_stamp_history where document_id='{0}' and request is NOT NULL".format(
                    document_id))
            if _request_data:
                _request_data = json.loads(_request_data[0].get('request'))
                for i in _request_data.get('invitations'):
                    if i.get('signUrl') == data.get('signUrl'):
                        i.update({'active': False})
                _request_data = json.dumps(_request_data)
                response = _execute_query(mydb.UPDATE, mydb._gen_update_query('e_sign_stamp_history', ['request'], {
                    'request': _request_data}) + ",invitees_remain=invitees_remain-1,del_invitees=del_invitees+1 where document_id='{0}'".format(
                    document_id))
                result = _get_result_as_dict(
                    query_parser.get('e_sign_stamp', '_get_deleted_invitees_list').format(document_id))
                if result[0].get('invitees_remain') == 0 and result[0].get('is_signed') == 0:
                    _execute_query(mydb.DELETE,
                                   "DELETE from e_sign_stamp_history where document_id='{0}'".format(document_id))
                    return jsonify({"status": "ERROR", "message": response})
                else:
                    return jsonify({"status": "ERROR", "message": response})
        else:
            return jsonify({"status": "ERROR", "message": _response})
    except req.exceptions.Timeout:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_timeout')})
    except req.exceptions.TooManyRedirects:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_too_many_redirects')})
    except req.exceptions.RequestException:
        return jsonify({"status": "ERROR", "message": error_parser.get('invalid', '_request_exception')})


@app.route('/api/loans/dealership/<int:dealership_id>/loans/<int:loan_id>/sanction', methods=['GET'])
@jwt_required
def _generate_sanction_letter_base64(dealership_id=None, loan_id=None):
    query = query_parser.get('dealership', '_loan_sanction_letter').format(loan_id, dealership_id)
    data = mydb.run_query(mydb.SELECT, query)
    if data:
        data = data[0]
        """The query is hard coded here since the schema redesign go live, afterwards we don't need this query we extract the dealers,coapplicants, gurantors from the single query."""
        query = "SELECT concat(ifnull(first_name,''),' ',ifnull(last_name,'')) as name FROM {} WHERE dealership_id = "+ str(dealership_id) +" and is_active is True"
        main_dealer_name = _get_result_as_dict(query.format('m_dealers') + " and is_main_applicant is True")
        if not main_dealer_name:
            return jsonify({'status':'ERROR','message':'Main applicant not found'})
        applicant_names = [main_dealer_name[0]]
        applicant_names.extend(_get_result_as_dict(query.format('m_dealers') + " and is_main_applicant is False"))
        applicant_names.extend(_get_result_as_dict(query.format('t_dealers_coapplicants')))
        applicant_names.extend(_get_result_as_dict(query.format('t_dealership_guarantors')))
        data.update({'applicant_names':' / '.join([i.get('name') for i in applicant_names]),
                    'main_dealer_name':main_dealer_name[0].get('name'),
                    'dealership_id': dealership_id})
        """Converting numbers to words using for loop"""
        data.update({key+'_in_words':num2words(str(data.get(key))) for key in ['approved_loan_amount','processing_fee','rate_of_interest']})
        """Converting numbers to amount using for loop"""
        data.update({key:format_currency(data.get(key), 'INR', locale='en_IN').replace('₹','<span style="font-family:dejavusanscondensed">&#x20b9;</span>') for key in ['approved_loan_amount','interest','repayable']})
        _sanction_letter_template = app.config['SANCTION_LETTER_TEMPLATE']
        _target_file_path = app.config['TARGET_FILE_PATH'] + "/{}/".format(str(dealership_id))
        _file_name = "{}_sanction_letter.html".format(dealership_id)
        _pdf_name = "{}_sanction_letter.pdf".format(dealership_id)
        _sanction_letter = _find_and_replace(_sanction_letter_template, _target_file_path, _file_name, data)
        options.update({'header-html': 'template/header.html'})
        with open(_sanction_letter) as fin:
            logger.debug("Generating sanction letter...")
            pdfkit.from_file(fin, os.path.join(_target_file_path, "sanction_letter.pdf"), options=options,
                             configuration=_wkhtml_config)
        message_bytes = open(os.path.join(_target_file_path, "sanction_letter.pdf"), "rb").read()
        file_bytes = base64.b64encode(message_bytes)
        file_message = file_bytes.decode('ascii')
        _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(str(dealership_id), _pdf_name,
                                                                                  dealership_docs_bucket, file_message)
        if _upload_status:
            return jsonify(
                {"status": "SUCCESS", "message": "PDF", "file": _uploaded_file_url})
        return jsonify({'status': 'ERROR', 'message': 'Unable to Download data'})
    else:
        return jsonify(
            {"status": "ERROR",
             "message": "Unable to generate sanction letter."+_support_message})


@app.route('/api/loans/dealership/<int:dealership_id>/loans/<int:loan_id>/application', methods=['GET'])
@jwt_required
def _generate_application_letter(dealership_id=None, loan_id=None):
    logger.debug("Generating application letter for approved loan, id:{}".format(str(loan_id)))
    _cur_date = datetime.date.today()
    query = query_parser.get('dealership', '_loan_sanction_letter_application').format(dealership_id)
    data = mydb.run_query(mydb.SELECT, query)
    data = decrypt_data(data, True)
    _dealers = mydb.run_query(mydb.SELECT, query_parser.get("dealers", "_get_associated_dealers").format(dealership_id))
    _dealers = decrypt_data(_dealers, True)
    _coapplicants = mydb.run_query(mydb.SELECT, query_parser.get("coapplicants", "_get_associated_coapplicants").format(
        dealership_id))
    _coapplicants = decrypt_data(_coapplicants, True)
    _guarantors = mydb.run_query(mydb.SELECT,
                                 query_parser.get("guarantors", "_get_associated_guarantors_by_id").format(
                                     dealership_id))
    _guarantors = decrypt_data(_guarantors, True)
    if not all([i.get('profile_image_url') for i in list(_dealers) + list(_coapplicants) + list(_guarantors)]):
        return jsonify({"status": "ERROR", "message": " Dealer/Co-applicant/Gurantor profile image not found"})
    if data:
        data[0].update({"dealership_id": dealership_id})
        data[0].update({"date": "{}-{}-{}".format(_cur_date.day, _cur_date.month, _cur_date.year)})
        data[0].update({"occupied_since": (
            int(_cur_date.year) - int(data[0].get('business_age')) if data[0].get('business_age') else _cur_date.year)})
        data = data[0]
        borrower = []
        borrower.append(_dealers[0])
        del _dealers[0]
        dealer_details = []
        dealer_details.extend(_dealers)
        dealer_details.extend(_coapplicants)
        data.update({"_dealers": _list_to_string("_dealers", borrower)})
        data.update({"_coapplicants": _list_to_string("_coapplicants", dealer_details)})
        data.update({"_guarantors": _list_to_string("_coapplicants", _guarantors)})
        data.update({"borrower": _list_to_string("dealer_details", borrower)})
        data.update({"co_borrower": _list_to_string("dealer_details", dealer_details)})
        data.update({"guarantors": _list_to_string("dealer_details", _guarantors)})

        _application_template = app.config['APPLICATION_TEMPLATE']
        _target_file_path = app.config['PROJECT_DIR'] + "/data/document/{}/".format(str(dealership_id))
        _file_name = "{}_application.html".format(dealership_id)
        _pdf_name = "{}_application.pdf".format(dealership_id)
        _application = _find_and_replace(_application_template, _target_file_path, _file_name, data)
        options.update({'header-html': 'template/header.html'})
        with open(_application) as fin:
            logger.debug("Generating application letter...")
            try:
                pdfkit.from_file(fin, os.path.join(_target_file_path, _pdf_name), options=options,
                                 configuration=_wkhtml_config)
            except Exception as e:
                error_message = "Error in application PDF generation because : {}".format(e)
                logger.error(error_message)
                error_alert(e,
                            message="Unable to generate Application letter."+_support_message)
                return jsonify({"status": "ERROR",
                                "message": "Unable to generate Application letter."+_support_message})
        message_bytes = open(os.path.join(_target_file_path, _pdf_name), "rb").read()
        file_bytes = base64.b64encode(message_bytes)
        file_message = file_bytes.decode('ascii')
        _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(str(dealership_id), _pdf_name,
                                                                                  dealership_docs_bucket, file_message)
        if _upload_status:
            return jsonify({"status": "SUCCESS", "message": "PDF", "file": _uploaded_file_url})
        return jsonify({'status': 'ERROR', 'message': 'Unable to Download data'})
    return jsonify(
        {"status": "ERROR",
         "message": "The application did not get generated because of one or all of the following reasons:\n \
            1. The dealership do not have any loan associated.\n \
            2. No dealer is present.\n \
            3. None of the dealer present is neither main applicant nor inactive.\n \
            If all these reasons checks out,"+_support_message})


def _get_template(_template_name=None):
    _file = open(app.config['TEMPLATE_DIR'] + "/" + _template_name + '.html', "r")  # get template from key_value k
    _file_temp = _file.read()
    _file.close()
    return _file_temp


@app.route('/api/dealership/<int:dealership_id>/pdr', methods=['GET'])
@app.route('/api/dealership/<int:dealership_id>/email/pdr', methods=['POST'])
@jwt_required
def _generate_pdr_report(dealership_id=None):
    logger.debug("Generating PDR report for dealership with dealership_id:{}".format(str(dealership_id)))
    _cur_date = datetime.date.today()
    data = {}
    dealer_data = mydb.run_query(mydb.SELECT,
                                 query_parser.get("dealers", "_get_dealer_details_by_id").format(dealership_id))
    if not dealer_data:
        return jsonify({'status': 'ERROR', 'message': 'No dealers found.'})
    dealership_data = mydb.run_query(mydb.SELECT,
                                     query_parser.get("dealership", "_get_dealership_by_id").format(dealership_id))
    _data = get_pdr(dealership_id)
    if dealership_data:
        data.update({"date": _cur_date.strftime('%d-%m-%Y')})
        data.update((_data.get('dealership_data'))[0])
        data.update(dealer_data[0])
        data.update((_data.get('outlet_data'))[0])
        data.update({"expense_details": _list_to_string("expense_details", _data.get("expense_details"))})
        data.update((_data.get("infrastructure_details"))[0])
        data.update({"bank_details": _list_to_string("bank_details", _data.get("bank_details"))})
        data.update({"loan_details": _list_to_string("loan_details", _data.get("loan_details"))})
        data.update((_data.get("monthly_obligation"))[0])
        if len(_data.get("tanker_details")[0]):
            data.update({"no_of_tanker": len(_data.get("tanker_details"))})
        data.update({"tanker_details": _list_to_string("tanker_details", _data.get("tanker_details"))})
        data.update((_data.get("business_details"))[0])
        data.update({"income_details": _list_to_string("income_details", _data.get("income_details"))})
        data.update({"references": _list_to_string("references", _data.get("references"))})
        data.update({"other_details": _list_to_string("other_details", _data.get("other_details"))})
        if _data.get("partner_details")[0]:
            data.update({"no_of_partners": len(_data.get("partner_details"))})
        data.update({"partner_details": _list_to_string("partner_details", _data.get("partner_details"))})
        data.update({"asset_details": _list_to_string("asset_details", _json_to_string(_data.get("asset_details")))})
        data.update({"client_details": _list_to_string("client_details", _data.get("client_details"))})
        if (_data.get("business_details"))[0]:
            data.update({"no_of_nozzles": ((_data.get("business_details"))[0]).get("hsd_count") + (
                (_data.get("business_details"))[0]).get("ms_count")})
        if not ((_data.get("dealership_data"))[0].get("pdr_remarks")):
            data.update({"pdr_remarks": "No remarks"})
        _pdr_template = app.config['PDR_TEMPLATE']
        _target_file_path = app.config['PROJECT_DIR'] + "/data/document/{}/".format(str(dealership_id))
        _file_name = "{}_pdr_report.html".format(dealership_id)
        _pdf_name = "{}_pdr_report.pdf".format(dealership_id)
        _pdr_report = _find_and_replace(_pdr_template, _target_file_path, _file_name, data)
        pdr_options = options.copy()
        pdr_options.update({'footer-html': 'template/pdr_footer.html'})
        pdr_options.update({'header-html': 'template/pdr_header.html'})
        pdr_options.update({'margin-top': '1.0in'})
        with open(_pdr_report) as fin:
            logger.debug("Generating Personal Discussion Report.....")
            pdfkit.from_file(fin, os.path.join(_target_file_path, _pdf_name), options=pdr_options,
                             configuration=_wkhtml_config)
        # TODO pass sending email as an argument instead of searching it from the base URL
        if "email" in request.base_url:
            msg = {}
            files_to_attach = []
            files_name = []
            pdr_recipients = []
            file_to_attach = _target_file_path + "{}_pdr_report.pdf".format(dealership_id)
            default_recipient = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_default_pdr_email'))
            custom_recipient = mydb.run_query(mydb.SELECT,
                                              query_parser.get('users', '_get_fo_sh_email_pdr').format(dealership_id))
            if len(custom_recipient) > 0:
                pdr_email_list = default_recipient + custom_recipient
            else:
                pdr_email_list = default_recipient
            for id in pdr_email_list:
                pdr_recipients.append(id.get('email'))
            msg.update({"subject": "Personal Discussion Report of {} ({})".format(
                dealer_data[0].get('dealer_name'), dealership_id)})
            msg.update({
                "body": "Dear Sir/Madam,\nGreetings!\n\nA detailed Personal Discussion Report for {} (dealership ID: {}) is attached below".format(
                    dealer_data[0].get('dealer_name'), dealership_id)})
            msg.update({"recipients": pdr_recipients})
            files_to_attach.append(file_to_attach)
            _pdf_name = "{}_pdr_report.pdf".format(dealership_id)
            files_name.append(_pdf_name)
            email_status = _send_mail(msg, attachment=files_to_attach, file_name=files_name)
            os.remove(_pdr_report)
            os.remove(os.path.join(_target_file_path, _pdf_name))
            if email_status:
                return jsonify({"status": "SUCCESS", "message": "PDR Report emailed successfully",
                                "email status": email_status.get_json()})
            return jsonify({"status": "ERROR", "message": "Failed to send PDR report over an email"})
        message_bytes = open(os.path.join(_target_file_path, _pdf_name), "rb").read()
        file_bytes = base64.b64encode(message_bytes)
        pdr_file_data = file_bytes.decode('ascii')
        os.remove(_pdr_report)
        os.remove(os.path.join(_target_file_path, _pdf_name))
        _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(str(dealership_id), _pdf_name,
                                                                                  dealership_docs_bucket, pdr_file_data)
        if _upload_status:
            return jsonify(
                {"status": "SUCCESS", "message": "PDR report generated successfully", "file": _uploaded_file_url})
        return jsonify({"status": "ERROR", "message": "error in file generation or reading file"})
    else:
        return jsonify(error_parser.get('invalid', '_id_details_missing'), 200)


def get_pdr(dealership_id=None):
    if dealership_id:
        data = {}
        section = [["dealership", "_get_dealership_by_id_pdr"], ["outlet", "_get_outlet_data_by_id"],
                   ["dealership", "_get_expense_details_pdr"], ["infrastructure", "_get_infrastructure_data_by_id"],
                   ["dealership", "_get_bank_details"], ["loans_ext", "_get_loans_with_type"],
                   ["loans_ext", "_get_monthly_obligation"], ["tanker", "_get_tanker_data_by_id"],
                   ["dealership", "_get_business_details_pdr"], ["dealership", "_get_income_details_with_type"],
                   ["coapplicants", "_get_associated_coapplicants"], ["dealership", "_get_asset_details_by_id"],
                   ["dealership_transporter", "_get_client_details"], ["references", "_get_references_by_id"],
                   ["details", "_get_other_details_by_id"]]

        key = ["dealership_data", "outlet_data", "expense_details", "infrastructure_details", "bank_details",
               "loan_details", "monthly_obligation", "tanker_details", "business_details", "income_details",
               "partner_details", "asset_details", "client_details", "references", "other_details"]
        for i in range(len(section)):
            query = mydb.run_query(mydb.SELECT, query_parser.get(section[i][0], section[i][1]).format(dealership_id))
            if query:
                data.update({key[i]: mydb.run_query(mydb.SELECT, query_parser.get(section[i][0], section[i][1]).format(
                    dealership_id))})
            else:
                data.update({key[i]: [{}]})
        return data


def _list_to_string(_template_name=None, _data=None, _res=""):
    _file = open(app.config['TEMPLATE_DIR'] + "/" + _template_name + '.html', "r")  # get template from key_value k
    _file_temp = _file.read()
    _file.close()
    for _val in range(len(_data)):
        _template = _file_temp
        for _k, _v in _data[_val].items():
            if _v:
                _template = _template.replace("#" + _k + "#", str(_v))
        _res = _res + _template
    return _res


def _json_to_string(data=None):
    if len(data[0]):
        for j in data:
            dealer_dict = json.loads(j.get("details"))
            master_dict = json.loads(j.get("m_details"))
            dealer_keys = dealer_dict.keys()
            dealer_keys = list(dealer_keys)
            for k in dealer_keys:
                for v in master_dict:
                    if k == v.get("key"):
                        j.update({"details": j.get("details").replace(k, v.get("label"))})
        for key in data:
            str_key = key.get("details").replace("{", " ").replace("}", "").replace('"', " ").replace(",", "</br>")
            key.update({"details": str_key})
        return data
    return [{}]


def _current_fy():
    _cur_date = datetime.date.today()
    from_year = _cur_date.year if _cur_date.month > 3 else _cur_date.year - 1
    return from_year


@app.route('/api/dealership/<int:dealership_id>/soa', methods=['GET'])
@jwt_required
def _soa_report(dealership_id=None):
    return _get_soa(dealership_id)


def _get_soa(dealership_id=None, _from_date=None, _to_date=None):
    if dealership_id:
        query = query_parser.get('dealership', '_get_applicant_code').format(dealership_id)
        applicant_code = mydb.run_query(mydb.SELECT, query)
        if applicant_code:
            applicant_code = applicant_code[0].get('applicant_code')
        else:
            return jsonify({"status": "ERROR",
                            "message": "Applicant code not found. "+_support_message})
        if all([_from_date, _to_date]):
            from_date = _direct_format_date(_from_date)
            to_date = _direct_format_date(_to_date)
            cur_date = _direct_format_date(datetime.date.today().strftime('%d-%m-%Y'))
        else:
            from_date = _direct_format_date(request.args.get('from_date'))
            to_date = _direct_format_date(request.args.get('to_date'))
            cur_date = _direct_format_date(datetime.date.today().strftime('%d-%m-%Y'))
        if os.getenv("CURRENT_LMS_SYSTEM") == "mifin":
            payload = {"JASPER_NAME": "CUSTOMER_SOA.jasper",
                       "searchCriteria": "APPLICANTCODE~VARCHAR2~=~'" + applicant_code +
                                         "'^FROM_DATE~DATE~=~'" + from_date +
                                         "'^TO_DATE~DATE~=~'" + to_date + "'",
                       "ACTIONID": "4000000089", "USERID": "1100000423", "VIEWMODE": "E", "BUSINESSDATE": cur_date,
                       "APP_VERSION": "1.0.0.0.4"}
            url = "https://loanpetromoney.com/MifinHLServiceRetroUniqueRequest/qc/mifinhl/getSoaGLReportData"
            response = req.request("POST", url, json=payload)
            result = response.json()
            _pdf_name = '{}_soa.pdf'.format(dealership_id)
            if result.get('StreamData'):
                file_message = result.get('StreamData')
                _s3_file_prefix = str(dealership_id)
                _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(_s3_file_prefix, _pdf_name,
                                                                                          dealership_docs_bucket,
                                                                                          file_message)
                if result.get('Status') == 'S' and result.get('StreamData'):
                    if _upload_status:
                        return jsonify(
                            {"status": "SUCCESS", "message": result.get('Message'), "file": _uploaded_file_url})
                    return jsonify({'status': 'ERROR', 'message': 'Unable to download data'})
                return jsonify({"status": "ERROR", "message": "Request failed."+_support_message})
            return jsonify({"status": "ERROR", "message": "Request failed."+_support_message})
        else:
            return jsonify(_lms_data_handler(None, "statement_of_accounts",
                                     {"customer_id" : dealership_id, "from_date" : from_date, "to_date" : to_date}))
    return jsonify(error_parser.get('invalid', '_id_not_found'), 200)


def _direct_format_date(data=None):
    if data:
        return datetime.date.strftime((datetime.datetime.strptime(data, '%d-%m-%Y')), '%d-%b-%Y')
    return data


def _send_mail(mail_data, attachment=None, file_name=None, file_type="application/pdf", file_buffer=None):
    try:
        mail = Mail()
        app.config.update(mail_config)
        mail.init_app(app)
        message = _get_email_message_context(mail_data.get('subject'), _email_recipients=mail_data.get('recipients'),
                                             cc=mail_data.get('cc'),
                                             body=mail_data.get('body'))
        if attachment:
            for sub_attachment, name in itertools.zip_longest(attachment, file_name):
                with app.open_resource(sub_attachment) as fp:
                    message.attach(name, file_type, fp.read())
        if file_buffer:
            for fp, name in zip(file_buffer, file_name):
                message.attach(name, file_type, fp.getvalue())
        logger.debug("Email send request initiated.....")
        mail.send(message)
        return jsonify({"message": "Email sent successfully.", "delivery": True})
    except Exception as e:
        logger.debug("Email error---->: {}".format(e))
        return jsonify({"message": "Email failed."+_support_message, "delivery": False})

def _get_email_message_context(subject="Test email subject", sender=None, _email_recipients=None, cc=None,
                               body="Test body content",
                               attachments=""):
    if sender is None:
        sender = app.config.get('MAIL_USERNAME')
    msg = Message(subject=subject,
                  sender=sender,
                  recipients=_email_recipients,
                  cc=cc,
                  body=body,
                  attachments=attachments)
    return msg


def _file_upload_local(file, dealership_id=None, operation='INSERT'):
    dir_path = os.getcwd()
    folder_path = ""
    file_url = ""
    if dealership_id:
        folder_path = dir_path + "/" + app.config['UPLOAD_FOLDER'] + "/" + str(dealership_id)
        file_url = app.config['UPLOAD_FOLDER'] + "/" + str(dealership_id)
    else:
        logger.debug("Dealership details are missing in folder path.")
        return jsonify({"status": "ERROR", "message": "File could not be uploaded. "+_support_message})

    if operation == 'INSERT':

        if file.filename == '':
            return jsonify({"status": "ERROR", "message": "Select a file to upload."})

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)
            file.save(os.path.join(folder_path, filename))
            return "https://api.petromoney.in/" + file_url + "/" + filename
        else:
            return jsonify(
                {"status": "ERROR",
                 "message": "Only files with 'pdf', 'png', 'jpg', 'jpeg', 'xls', 'xlsx', 'csv' extensions are allowed. "})

    if operation == 'DELETE':
        filename = file.rsplit('/', 1)[-1]
        try:
            if os.path.isfile(os.path.join(folder_path, filename)):
                os.remove(os.path.join(folder_path, filename))
                return True
        except OSError as e:
            return False


def image_to_jpeg_bytes(file):
    img = Image.open(file)
    img = img.convert('RGB')
    img = img.resize(img.size, Image.LANCZOS)
    img_buffer = io.BytesIO()
    img.save(img_buffer, format='JPEG', quality=30)
    image_bytes = base64.b64encode(img_buffer.getvalue())
    return image_bytes


def get_allowed_file_args(**kwargs):
    if kwargs.get('doc_id') == OTHER_DOCUMENTS_ID:
        kwargs.update({'extensions': [*ALLOWED_DOC_EXTENSIONS, *ALLOWED_MEDIA_EXTENSIONS]})
    kwargs.pop('doc_id')
    return kwargs


def _file_upload(files, origin_id=None, id=None, doc_id=None, type=None):
    if origin_id:
        _file_urls = []
        _query_result = mydb.run_query(mydb.SELECT, query_parser.get('checklist', '_get_document_name').format(doc_id))
        doc_name = _query_result[0].get('doc_name')
        _s3_file_prefix = str(origin_id) + "/" + doc_name
        if id is not None:
            _s3_file_prefix = _s3_file_prefix + "/" + str(id) + "/" + doc_name
        for file in files:
            if file and allowed_file(**get_allowed_file_args(filename=file.filename, doc_id=doc_id)):
                filename = secure_filename(file.filename)
                if type == 'dealers':
                    if filename.split('.')[-1].upper() in ['JPG', 'JPEG', 'PNG']:
                        _upload_status, _uploaded_file = _s3fileupload._s3_base64_file_upload(_s3_file_prefix, filename,
                                                                                              dealership_docs_bucket,
                                                                                              image_to_jpeg_bytes(file))
                    else:
                        _upload_status, _uploaded_file = _s3_file_upload(_s3_file_prefix, filename,
                                                                         dealership_docs_bucket, file)
                elif type == 'transport':
                    if filename.split('.')[-1].upper() in ['JPG', 'JPEG', 'PNG']:
                        _upload_status, _uploaded_file = _s3fileupload._s3_base64_file_upload(
                            "transporters/" + _s3_file_prefix, filename, transporter_docs_bucket,
                            image_to_jpeg_bytes(file))
                    else:
                        _upload_status, _uploaded_file = _s3_file_upload(_s3_file_prefix, filename,
                                                                         transporter_docs_bucket, file)
                if _upload_status:
                    _file_urls.append(_uploaded_file)
                else:
                    return None, "File could not uploaded. Please try again."
            else:
                return None, "No file is selected for upload or the file has an extension other than '.pdf', '.png','.jpg', '.jpeg', '.xls', '.xlsx', '.csv'"
        return " ".join(str(x) for x in _file_urls), True
    else:
        return None, "File could not be uploaded. "+_support_message


def _vehicle_file_upload(files, transporter_id=None, vehicle_id=None, document_name=None, doc_id=None):
    if transporter_id and vehicle_id:
        _file_urls = []
        _file_urls = []
        _query_result = mydb.run_query(mydb.SELECT, query_parser.get('checklist', '_get_document_name').format(doc_id))
        doc_name = _query_result[0].get('doc_name')
        _s3_file_prefix = str(transporter_id) + "/" + str(vehicle_id) + "/" + doc_name
        if document_name:
            _s3_file_prefix = str(transporter_id) + "/" + str(vehicle_id) + "/" + doc_name + "_" + document_name
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                _upload_status, _uploaded_file = _s3_file_upload("transporters/" + _s3_file_prefix, filename,
                                                                 transporter_docs_bucket, file)
                if _upload_status:
                    _file_urls.append(_uploaded_file)
                else:
                    return jsonify(
                        {"status": "ERROR", "message": "File could not be uploaded to S3. Please try again."})
            else:
                return jsonify(
                    {"status": "ERROR",
                     "message": "No file is selected for upload or the file has an extension other than '.pdf', '.png', "
                                "'.jpg', '.jpeg', '.xls', '.xlsx', '.csv'"})
        return True, " ".join(str(x) for x in _file_urls)
    else:
        logger.debug("Vehicle document details are missing in function call.")
        return jsonify({"status": "ERROR", "message": "File upload failed. "+_support_message})


def get_column_by_file_type(type):
    if type == "PAN":
        return "pan_file_url"
    elif type == "AADHAAR_FRONT":
        return "aadhar_f_file_url"
    elif type == "AADHAAR_BACK":
        return "aadhar_b_file_url"
    elif type == "GST":
        return "gst_file_url"


def _get_file_content_type(_file_to_upload):
    if _file_to_upload:
        return content_type_map.get(_file_to_upload.rsplit('.', 1)[1].lower())


def _s3_file_upload(_file_prefix, _file_name, _bucket_name, _file_object, uid=False):
    _file_to_upload = _file_prefix + "/{0}".format(_file_name if uid else str(uuid.uuid4()) + "___" + _file_name)
    _upload_status = False
    _uploaded_file = ""
    client = boto3.client('s3')
    try:
        _upload_response = client.put_object(Body=_file_object.read(), Bucket=_bucket_name, Key=_file_to_upload,
                                             ContentType=_get_file_content_type(_file_to_upload))
        if _upload_response:
            _upload_status = True
            _uploaded_file = docs_url + "/" + _file_to_upload
    except Exception as e:
        logger.debug("File upload to s3 failed because: {}", format(e))
    return _upload_status, _uploaded_file


def _is_rows_affected(query, _update_status=False, stage_id=0, dealership_id=0):
    affected_rows = mydb.run_query(mydb.INSERT, query)
    if (affected_rows > 0) or _update_status:
        profile_status = _check_profile_status_and_upsert(_update_status, stage_id, dealership_id)
        return jsonify({'status': 'SUCCESS',
                        'message': 'Updated recorded successfully.',
                        'affected_rows': affected_rows,
                        'profile_status': profile_status})
    else:
        return jsonify({'status': 'ERROR', 'message': 'Failed to add the record.'})


def _execute_query_with_status(query_type, query, _update_status=False, stage_id=0, dealership_id=0):
    affected_rows, last_insert_id = mydb.run_query(query_type, query, row_insert_id=True)
    if affected_rows > 0:
        profile_status = _check_profile_status_and_upsert(_update_status, stage_id, dealership_id)
        return jsonify({'status': 'SUCCESS', 'affected_rows': affected_rows, 'row_id': last_insert_id,
                        'profile_status': profile_status, 'message':'The record is added/modified successfully'})
    else:
        return jsonify({'status': 'ERROR', 'message': 'Failed to add the record.'})


def _execute_query(query_type, query, success_message='Record add/update/remove was successful.',
                   fail_message='Failed to add the record.'):
    if query_type == "proc":
        affected_rows, last_insert_id = mydb.run_procedure(query, row_insert_id=True)
    else:
        affected_rows, last_insert_id = mydb.run_query(query_type, query, row_insert_id=True)
    if affected_rows > 0:
        return jsonify(
            {'status': 'SUCCESS', 'message': success_message, 'affected_rows': affected_rows, 'row_id': last_insert_id})
    elif affected_rows == 0:
        return jsonify({'status': 'ERROR', 'message': 'No record was updated.', 'affected_rows': affected_rows,
                        'row_id': last_insert_id})
    else:
        return jsonify({'status': 'ERROR', 'message': fail_message})


def _check_profile_completion_status(dealership_id=None):
    _status_check_for_list = [1, 2, 3]
    _status_list = [e['stage_id'] for e in (
        _get_result(query_parser.get('dealership', '_get_profile_status_list').format(dealership_id))).get_json().get(
        'data')]
    status = all(elem in _status_list for elem in _status_check_for_list)
    incomplete_stage = [i for i in _status_check_for_list if i not in _status_list]
    return jsonify(
        {"completion_status": status, "stages_complete": _status_list, "stages_incomplete": incomplete_stage})


def _check_profile_status_and_upsert(_update_status=False, stage_id=0, dealership_id=0):
    if _update_status and stage_id > 0 and dealership_id > 0:
        _is_exists = mydb.run_query(mydb.SELECT,
                                    query_parser.get('dealership', '_if_status_exists').format(stage_id, dealership_id))
        if len(_is_exists) < 1:
            mydb.run_query(mydb.INSERT,
                           query_parser.get('dealership', '_post_profile_completion_status').format(dealership_id,
                                                                                                    stage_id))
            return "status updated"
        else:
            return "Profile exists/updated, no status update required."
    else:
        return "status updated already"


def _get_json(data):
    return json.loads(data)


def _get_result(query):
    result = mydb.run_query(mydb.SELECT, query)
    return jsonify({'status': 'SUCCESS', 'data': result})


def _get_result_as_json(query,keys_to_convert_into_json):
    results = _get_result_as_dict(query)
    for keys_to_convert in keys_to_convert_into_json:
        for index in range(len(results)):
            value = results[index].get(keys_to_convert)
            if value:
                results[index].update({keys_to_convert:json.loads(value)})
    return jsonify({'status': 'SUCCESS', 'data': results})


def _get_result_as_dict(query):
    return mydb.run_query(mydb.SELECT, query)


def _is_empty(val):
    return False if val else True


def _format_files_data(data, key):
    sorted_data = sorted(data, key=itemgetter(key))
    file_data = []
    for key, value in groupby(sorted_data, key=itemgetter(key)):
        files = []
        for i in value:
            file_url = file_name = file_type = ""
            if i.get('file_path'):
                file_url = i.get('file_path')
                if '___' in i.get('file_path'):
                    file_name = i.get('file_path').split('___')[1]
                else:
                    file_name = i.get('file_path').split('/')[-1]
                file_type = _get_file_type(i.get('file_path'))
            files.append({'file_id': i.get('id'), 'file_url': file_url,
                          'file_type': file_type,
                          'file_name': file_name,
                          'created_date': i.get('created_date'),
                          'modified_date': i.get('modified_date'),
                          'modified_by': i.get('modified_by')})
            i.pop("id")
            i.pop("file_path")
            i.pop('created_date')
            i.pop('modified_date')
            i.pop('modified_by')
            i.update({"file_data": files})
        if i:
            file_data.append(i)
    return file_data


def _lms_data_handler(section,option,data = {}, use_mifin = True):
    if os.getenv('CURRENT_LMS_SYSTEM') == 'mifin' and use_mifin:
        query = query_parser.get(section,option)
        return _get_data_from_lms(query.format(**data))
    else:
        _data = _get_result_as_dict(query_parser.get('external','_get_external_api_value').format('LMS'))[0]
        url = _data.get(f'base_url_{ENVIRONMENT.lower()}') + _data.get('api_path')
        payload = {'entity': option, 'data': data}
        headers = json.loads(_data.get(f'{ENVIRONMENT.lower()}_header'))
        response = req.post(url, json = payload, headers = headers)
        if response.status_code == 200:
            return response.json().get('data')
        logger.error(f"Couldn't get valid response from LMS \n URL -> {url} \n Payload -> {payload} \n Headers -> {headers} \n Response -> {response.text}")
        raise Exception("Couldn't get valid response from LMS")


def _get_data_from_lms(query):
    logger.debug("Query to Oracle DB LMS: %s", query)
    _start_time = time()
    cnxn = _get_lms_connection()
    cursor = cnxn.cursor()
    cursor.execute(query)
    column_names_list = [x[0].lower() for x in cursor.description]
    result = [dict(zip(column_names_list, row)) for row in cursor.fetchall()]
    cnxn.close()
    logger.info(f"Oracle query execution time {time() - _start_time} seconds")
    return result


def _execute_lms_query(query):
    if os.getenv('CURRENT_LMS_SYSTEM') == 'mifin':
        logger.debug("Query to Oracle DB LMS: %s", query)
        _start_time = time()
        cnxn = _get_lms_connection()
        cursor = cnxn.cursor()
        result = cursor.execute(query)
        cnxn.commit()
        cnxn.close()
        logger.info(f"Oracle query execution time {time() - _start_time} seconds")
        return result
    else:
        logger.error("Couldn't execute lms query, because current lms system is not mifin")


def _get_lms_connection():
    return cx_Oracle.connect(ORACLE_URI)


def _hash_password(password):
    # """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def _verify_password(stored_password, provided_password):
    # """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password


@app.route('/api/vkyc/log', methods=['PUT'])
def vkyc_log():
    data = request.get_json()
    file_name = data.get('requestId', '_') + '_' + data.get('customerId', '_') + '.json'
    json_to_bytes = base64.b64encode(json.dumps(data, indent=4).encode('utf-8'))
    file_to_store = 'vkyc' + '/' + data.get('customerId') if data.get('customerId') else 'vkyc'
    _upload_status, _uploaded_file_url = _s3fileupload._s3_base64_file_upload(file_to_store, file_name,
                                                                              dealership_docs_bucket, json_to_bytes)
    if not _upload_status:
        logger.info('Unable to store the log file for dealership_id {}.'.format(data.get('customerId')))
    return jsonify({'status': 'SUCCESS'})


@app.route('/api/otp/send', methods=['POST'])
def otp_send():
    data = request.get_json()
    mobile = data.get('mobile')
    regex = "^[0-9]{10}$"
    if re.search(regex, str(mobile)):
        return send_otp(mobile, OTP_TEMPLATE, 2)
    return {"status": "ERROR", "message": "Please enter valid mobile number"}


def send_otp(mobile, template_id=None, otp_expiry=1):
    response = req.post('https://api.msg91.com/api/v5/otp', params={
        'invisible': '1',
        'authkey': SMS_API_AUTH_KEY,
        'mobile': '+91' + str(mobile),
        'template_id': template_id,
        'otp_expiry': otp_expiry
    })
    return validate_msg91_response(response)


@app.route('/api/otp/resend', methods=['POST'])
def resend_otp():
    data = request.get_json()
    mobile = str(data.get('mobile'))
    regex = "^[0-9]{10}$"
    if re.search(regex, str(mobile)):
        retry_type = data.get('retry_type', 'text')
        response = req.post('https://api.msg91.com/api/v5/otp/retry', params={
            'mobile': '+91' + mobile,
            'authkey': SMS_API_AUTH_KEY,
            'retrytype': retry_type
        })
        return validate_msg91_response(response)
    return ({"status": "ERROR", "message": "Please enter valid mobile number"})


""" It's used to send the OTP while uploading the credit limit. """


@app.route('/api/credit/limit/otp/send', methods=['POST'])
def credit_limit_otp_send():
    data = request.get_json()
    regex = "^[0-9]{10}$"
    if re.search(regex, str(data.get('mobile'))):
        credit_limit_template_id = \
            _get_result_as_dict(query_parser.get('sms', '_get_template_id_using_name').format('credit_limit_OTP'))[
                0].get(
                'template_id')
        response = _send_otp(data.get('mobile'), credit_limit_template_id, 2, data)
        if response:
            return ({"status": "SUCCESS", "message": "OTP is send to Your Mobile Number"})
        return ({"status": "ERROR", "message": "Unable to Send the OTP. Please check the connection and try again."})
    return ({"status": "ERROR", "message": "Please Enter valid Mobile Number"})


def _send_otp(mobile, template_id=None, otp_expiry=1, data=None):
    payload = {"value1": data.get("transporter_name"), "value2": data.get("dealership_name"),
               "value3": data.get("amount")}
    headers = {"Content-Type": "application/json"}
    response = req.post('https://api.msg91.com/api/v5/otp', params={
        'invisible': '1',
        'authkey': SMS_API_AUTH_KEY,
        'mobile': '+91' + str(mobile),
        'template_id': template_id,
        'otp_expiry': otp_expiry
    })
    return response.json()


@app.route('/api/notify', methods=['POST'])
def _send_sms():
    auth = request.headers
    data = request.get_json()
    if auth.get('API_AUTH_KEY') == "[?shhUKG[gPf1R~N-fU7":
        conn = http.client.HTTPSConnection("api.msg91.com")
        headers = {
            'authkey': SMS_API_AUTH_KEY,
            'content-type': "application/JSON"
        }
        conn.request("POST", "/api/v5/flow", json.dumps(data), headers)
        response = json.loads(conn.getresponse().read().decode('utf-8'))
        response.update({"status": response.pop('type')})
        return response
    else:
        return jsonify({"status": "ERROR", "message": "User authentication failed. "+_support_message})


def verify_otp(mobile, otp):
    response = req.post('https://api.msg91.com/api/v5/otp/verify', params={
        'mobile': '+91' + str(mobile),
        'authkey': SMS_API_AUTH_KEY,
        'otp': otp
    })
    if response:
        response = response.json()
        if response.get('type') == 'success':
            return True, ""
        else:
            return False, response.get('message')
    else:
        return False, "Failed to verify the OTP. "+_support_message


def _get_user_regions(user_id):
    return _get_result_as_dict(query_parser.get('users', '_get_user_region_info').format(user_id))


def _get_products_by_role_id(role_id):
    return _get_result_as_dict(query_parser.get('users', '_get_role_product_info').format(role_id))


def _get_user_role(user_id):
    user_role = mydb.run_query(mydb.SELECT, query_parser.get('users', '_get_user_role').format(user_id))
    return user_role[0].get('role_id')


def _user_exists(user_id):
    _user_exists = _get_result_as_dict(
        "SELECT EXISTS(SELECT mobile FROM `m_users` where id={0}) as user_exists".format(user_id))
    return _user_exists[0].get('user_exists', 0)


def _is_main_applicant(mobile_no, dealership_id):
    _user_exists = _get_result_as_dict(
        "SELECT EXISTS(" + query_parser.get('dealers', '_get_main_dealer').format(dealership_id) + ") as user_exists")
    return _user_exists[0].get('user_exists', 0)


def _dealer_exists(mobile_no):
    _dealer_exists = _get_result_as_dict(query_parser.get('dealers', '_dealer_exists').format(mobile_no))
    return _dealer_exists[0].get('_dealer_exists', 0)


def _transporter_exists(transporter_id):
    _transporter_exists = _get_result_as_dict(
        "SELECT EXISTS(SELECT transporter_id from `t_transports` where transporter_id={0}) as transporter_exists".format(
            transporter_id))
    return _transporter_exists[0].get('transporter_exists', 0)


def _dealership_loan_exists(dealership_id, status=None):
    if status:
        _query = query_parser.get('dealership', '_loan_exists').format(dealership_id, "AND status='{}'".format(status))
    else:
        _query = query_parser.get('dealership', '_loan_exists').format(dealership_id, "")
    _loan_exists = _get_result_as_dict(_query)
    return _loan_exists[0].get('loan_exists', 0)


def _callback_request_exists(mobile):
    _request_exists = _get_result_as_dict(query_parser.get('whatsapp', '_callback_request_exists').format(mobile))
    return _request_exists[0].get('_request_exists', 0)


def num2words(num):
    num = decimal.Decimal(num)
    decimal_part = num - int(num)
    num = int(num)
    if decimal_part:
        return num2words(num) + " point " + (" ".join(num2words(i) for i in str(decimal_part)[2:]))
    under_20 = ['Zero', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine', 'Ten', 'Eleven',
                'Twelve', 'Thirteen', 'Fourteen', 'Fifteen', 'Sixteen', 'Seventeen', 'Eighteen', 'Nineteen']
    tens = ['Twenty', 'Thirty', 'Forty', 'Fifty', 'Sixty', 'Seventy', 'Eighty', 'Ninety']
    above_100 = {100: 'Hundred', 1000: 'Thousand', 100000: 'Lakhs', 10000000: 'Crores'}
    if num < 20:
        return under_20[num]
    if num < 100:
        return tens[num // 10 - 2] + ('' if num % 10 == 0 else ' ' + under_20[num % 10])
    pivot = max([key for key in above_100.keys() if key <= num])
    return num2words(num // pivot) + ' ' + above_100[pivot] + ('' if num % pivot == 0 else ' ' + num2words(num % pivot))


def _dict_to_string(type=None, _applicant=None):
    name = phone = email = address = ""
    for i in _applicant:
        name = name + i.get("first_name") + ' ' + i.get("last_name") + ','
        phone = phone + str(i.get("mobile", "-")) + ','
        email = email + "{}".format(i.get('email') if i.get('email') else '-' ) + ','
        address = address + i.get("address", "-") + ' / '
    return ({
        type + "_names": name[slice(0, -1)],
        type + "_number": phone[slice(0, -1)],
        type + "_mail": email[slice(0, -1)],
        type + "_address": address[slice(0, -1)],  # slice to remove the last unwanted symbol
    })


def _find_and_replace(_template_file=None, _target_file=None, _file_name=None, _key_values=None):
    _template = open(_template_file, "r")
    s = ""
    if not os.path.exists(_target_file):
        os.makedirs(_target_file)
    with open(os.path.join(_target_file, _file_name), "w", encoding = "utf-8") as _file:
        for line in _template:
            for k, v in _key_values.items():
                if v:
                    line = line.replace("#" + k + "#", str(v))
            if "#" in line:
                s = line[line.index("#") + 1:]
            if "#" in s:
                null_key = s.split("#")
                for i in null_key:
                    line = line.replace("#" + i + "#", "-")
            _file.write(line)
    _template.close()
    _file.close()
    return os.path.join(_target_file, _file_name)


def allowed_file(filename, extensions=ALLOWED_DOC_EXTENSIONS):
    if filename == '':
        return jsonify({"status": "ERROR", "message": "Select a file to upload."})
    else:
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in extensions


def _if_none_and_sum(result, key):
    sum = dict(reduce(add, map(Counter, result))).get(key)
    return sum if sum else 0


# TODO Cleanup this function to use ternary logic
def _get_file_type(filename):
    if filename:
        return '.' in filename and filename.rsplit('.', 1)[1].lower()
    else:
        return ""


def _check_duplicates(table_name, data, applicant_id=None):
    if applicant_id:
        return False
    _join = []
    result = ''
    for kyc in data:
        if kyc in ['pan', 'aadhar', 'mobile']:
            _join.append(' {0} = "{1}" '.format(kyc, data[kyc]))
    if _join:
        query = query_parser.get("dealership", "_kyc_exists").format(table_name, " OR ".join(_join))
        result = mydb.run_query(mydb.SELECT, query)
    return True if result else False


def pad(data):
    length = int(BLOCK_SIZE) - (len(data) % int(BLOCK_SIZE))
    return data + (chr(length) * length).encode()


def unpad(data):
    return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))].decode()


def bytes_to_key(data, salt, output=48):
    assert len(salt) == 8, len(salt)
    data += salt
    key = md5(data).digest()
    final_key = key
    while len(final_key) < output:
        key = md5(key + data).digest()
        final_key += key
    return final_key[:output]


def decrypt(encrypted, passphrase=CRYPT_BE_KEY):
    try:
        decode_encrypt = base64.b64decode(encrypted.encode())
        assert decode_encrypt[0:8] == b"Salted__"
        salt = decode_encrypt[8:16]
        key_iv = bytes_to_key(passphrase.encode(), salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        return unpad(aes.decrypt(decode_encrypt[16:]))
    except:
        return encrypted


def validate_client_credentials(f):
    """This is special function which auto authenticate the client information that are
    passed along in the headers of the request
    If authentication fails, it restricts the access to the api itself.
    This authentication cannot be done using JWT token because the client is going to be a third party
    """
    @wraps(f)
    def decorator(*args, **kwargs):
        client_id, secret_key = request.headers.get('X-Client-ID'), request.headers.get('X-Client-Secret')
        if client_id and secret_key and _get_result_as_dict(query_parser.get('general','_validate_client_id_and_secret_key').format(client_id, secret_key)):
            return f(*args, **kwargs)
        return jsonify(status = 'ERROR', message = 'Unauthorized request'), 403
    return decorator


@app.route('/api/webhook', methods=['POST'])
@validate_client_credentials
def webhook():
    """
    This validates the request and return data to external system accordingly
    Sample payload:
    {
	"entity":"_update_credit_reload_loan",
	"data":{
		"tranche_code": "",
		"utr": "",
		"reload_status": "",
		"crr_id":""
	}
    """
    payload = request.get_json()
    _check_fields_in_request_data(['entity'], payload)
    if payload.get('entity') == 'update_credit_reload_status':
        """Standardizing crr_attribute and its values for directly using them in the sql update query"""
        for crr_attribute, value in payload.get('data').items():
            if payload.get('data').get(crr_attribute):
                payload.get('data')[crr_attribute] = f"'{value}'"
            else:
                payload.get('data')[crr_attribute] = 'NULL'
    query = query_parser.get('lms_shared_data', payload.get('entity')).format(**payload.get('data'))
    if query.startswith('SELECT'):
        return jsonify(status='SUCCESS', data=_get_result_as_dict(query))
    else:
        return _execute_query(mydb.INSERT, query)


def _push_verified_banks_to_lms(account_no = None, bank_id = None):
    """Sends the verified banks to external system"""
    if not account_no and not bank_id:
        abort(jsonify({"status":"ERROR", "message":"Transaction failed because of insufficient data"}))
    query = query_parser.get('authenticate','_bank_details')
    if account_no:
        query = query.format('dbd.account_no',account_no)
    else:
        query = query.format('dbd.id',bank_id)
    bank_details = _get_result_as_dict(query)
    if bank_details:
        sqs_object.send_message(message_group_id = "credit-reload-request",
                                message = {'entity':'customer_bank', 'data': bank_details[0]})



def double_decrypt(encrypted, passphrase=CRYPT_FE_KEY):
    return decrypt(decrypt(encrypted), passphrase)


# TODO
# revert to original fn after data migration
def encrypt_data(data, double=False):
    return data


def decrypt_data(data, double=False):
    for _data in data:
        for key in SECURE_DATA:
            if key in _data and _data.get(key):
                if double:
                    _data.update({key: double_decrypt(_data.get(key))})
                else:
                    _data.update({key: decrypt(_data.get(key))})
    return data


@app.route('/api/dealership/<int:dealership_id>/scorecard', methods=['GET', 'POST'])
@jwt_required
def scorecard_excel_upload(dealership_id):
    user_id = get_jwt_identity()
    if request.method == 'POST':
        if request.files:
            file = request.files.get('file')
            _extension = file.filename.split('.')[-1].lower()
            if allowed_file(file.filename, extensions={'xlsx'}):
                file_name = secure_filename(file.filename)
                if _extension == 'xlsx':
                    _upload_status, _uploaded_file_url = _s3_file_upload(str(dealership_id),
                                                                         file_name,
                                                                         dealership_docs_bucket,
                                                                         file)
                    if _upload_status:
                        affected, sheet_id = mydb.run_query(mydb.INSERT,
                                                            mydb._gen_insert_query('t_scorecard_file_audit', {
                                                                'created_by': user_id, 'last_modified_by': user_id,
                                                                'dealership_id': dealership_id,
                                                                'file_name': file_name,
                                                                'file_url': _uploaded_file_url}),
                                                            row_insert_id=True)
                        if not sheet_id:
                            return jsonify(
                                {"status": "ERROR", "message": "Scorecard excel sheet audit failed", "file": None})
                    else:
                        return jsonify(
                            {"status": "ERROR", "message": "Scorecard excel sheet upload failed", "file": None})
                    scorecard_data = parse_and_save_scorecard_excel_sheet(file, dealership_id, user_id, sheet_id)
                    if scorecard_data.get("status").upper() == "SUCCESS":
                        set_latest_flag(sheet_id, dealership_id, "SUCCESS")
                        return jsonify({'status': 'SUCCESS', "message": "excel sheet successfully parsed"})
                    else:
                        set_latest_flag(sheet_id, dealership_id, "ERROR")
                        is_rollback_success = rollback_erred_scorecard_data(sheet_id, dealership_id)
                        return jsonify(
                            {'status': 'ERROR', "message": "Error parsing excel sheet. {}".format(
                                "Rolled back the changes" if is_rollback_success is True
                                else "Rollback failed. "+_support_message)})
            else:
                return jsonify({'status': 'ERROR',
                                'message': 'Invalid file format. Accepted file type is .xlsx only.'})
        else:
            return jsonify(
                {'status': 'ERROR', 'message': 'Excel file is empty. Please check the file before you upload'})
    if request.method == 'GET':
        return get_scorecard_data_from_tables(dealership_id)


def pretty_print():
    return request.get_json()


@app.route('/*', methods=['POST'])
def test():
    logger.info("Request header")


# Run Server
if __name__ == '__main__':
    logger.debug('Starting the application....')
    app.run(host="127.0.0.1", port="5000", debug="True")
