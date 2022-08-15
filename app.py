#!/usr/bin/env python3
# (C) Sergey Pechenko, 2021
import logging
import os
import pprint
import re
import urllib.request
import urllib.response
import urllib.parse
import urllib.error
import base64
import json
from flask import Flask, request
from template import J2

from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler

logging.basicConfig(level=logging.INFO)
JIRA_URL = os.getenv("JIRA_URL", None)
JIRA_USER = os.getenv("JIRA_ACCOUNT", None)
JIRA_PASSWORD = os.getenv("JIRA_PASSWORD", None)
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", None)
SLACK_TOKEN = os.getenv("SLACK_TOKEN", None)
for i in ["JIRA_URL", "JIRA_USER", "JIRA_PASSWORD", "SLACK_SIGNING_SECRET", "SLACK_TOKEN"]:
    if globals()[i] is None:
        logging.error(f"{i} is missing, exiting...")
        exit(1)
STORY_POINTS_ID = None
PREPARED_ISSUE_RE = re.compile('^[A-Z]+-[0-9]+$')
CLEANSER_RE = re.compile(r'[^\w\d \-]+', re.UNICODE)
COMMANDS = ['vote']
GLOBAL_VOTES = []
ID_OPTION = "option_select"
ID_VOTE = "send_vote"
ID_COMPLETE = "vote_complete"


class Vote(object):
    def __init__(self, vote_id=None, user_id=None, value=None):
        self.vote_id = vote_id
        self.__results = {}
        self.start = None
        self.active = False
        self.valid = False
        if user_id and value:
            self.start_vote()
            self.upsert_vote(user_id, value)

    def upsert_vote(self, user, value):
        if self.active is False:
            return
        self.__results.update({user: value})
        self.valid = True

    def remove_vote(self, user):
        if self.active is False:
            return
        self.__results.pop(user, None)
        if len(self.__results) == 0:
            self.valid = False

    def start_vote(self):
        # announce value, ask for participation
        self.active = True

    def stop_vote(self):
        self.active = False

    def median(self):
        if self.valid is False:
            return None
        tmp_list = [v for _, v in self.__results.items()]
        tmp_list.sort()
        res = tmp_list[len(tmp_list) // 2]
        return res


def simple_jira_request(url, method='GET', data=None, headers=None):
    if headers is None:
        headers = {}
    user = "plapobot"
    passwd = "s3uW5H8jmfHvKPu"
    dgst = base64.standard_b64encode(f"{user}:{passwd}".encode('utf-8'))
    r = urllib.request.Request(url=f"{JIRA_URL}{url}", data=data)
    r.method = method
    r.add_header("Accept", "application/json,*.*;q=0.9")
    r.add_header("Authorization", f"Basic {dgst.decode('utf-8')}")
    for k, v in headers.items():
        r.add_header(k, v)
    with urllib.request.urlopen(r) as f:
        if f.code == 204:
            result = True
        else:
            result = json.load(f)
    return result


def load_jira_config():
    all_fields = simple_jira_request("/rest/api/2/field/")
    for field in all_fields:
        if field['name'] == "Story Points":
            globals()['STORY_POINTS_ID'] = field['id']
            break


def read_jira_issue(issue_id):
    # 'summary' means title
    # 'labels' is obvious
    # 'description' = big text field for task
    p = urllib.parse.urlencode({'fields': 'summary,labels,description', 'properties': '*all'})
    url = f"/rest/api/2/issue/{issue_id}?{p}"
    issue = simple_jira_request(url)
    # response will look like
    # {'expand': 'renderedFields,names,schema,operations,editmeta,changelog,versionedRepresentations',
    #  'fields': {'description': 'Tst task description',
    #             'labels': [],
    #             'summary': 'As a developer, I can update story and task status '
    #                        'with drag and drop (click the triangle at far left of '
    #                        'this story to show sub-tasks)'},
    #  'id': '10009',
    #  'key': 'TST-10',
    #  'properties': {},
    #  'self': 'https://jira.plapobot.ru/rest/api/2/issue/10009'}
    return issue


def write_jira_issue(issue_id, value):
    # 'summary' means title
    # 'labels' is obvious
    # 'description' = big text field for task
    data = json.dumps({'fields': {STORY_POINTS_ID: int(value)}}).encode('utf-8')
    url = f"/rest/api/2/issue/{issue_id}"
    headers = {'Content-Type': 'application/json'}
    try:
        result = simple_jira_request(url, method='PUT', data=data, headers=headers)
    except urllib.error.HTTPError as e:
        logging.exception("Error", e)
        return None
    else:
        return result


app = App(signing_secret=SLACK_SIGNING_SECRET,
          token=SLACK_TOKEN)


@app.middleware  # or app.use(log_request)
def log_request(context, body, next):
    context.logger.info(pprint.pformat(body))
    return next()


@app.event({"type": "reaction_added"})
def reaction_handler(context, body):
    event = body.get("event", {})
    emoji = event.get("reaction", {})
    item = event.get("item", {})
    channel = item.get("channel", {})
    for i in [event, item, channel, emoji]:
        if i == {}:
            return
    msg = {'channel': channel, 'text': f"{emoji}"}
    context.say(**msg)


def prepare_result_payload(context):
    result = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"<@{context.user_id}>, спасибо! Итоговая оценка задачи {context.issue_key}: *{context.issue_value}*."
                }
            }
        ],
        "replace_original": "true"
    }
    return result


@app.block_action(ID_COMPLETE)
def complete_btn_handler(context, body, client, action):
    context.ack()
    result_vote = None
    barking_response = {"channel": body["channel"]["id"]}
    possibly_ts = body['message'].get('thread_ts', None)
    if possibly_ts:
        barking_response['thread_ts'] = possibly_ts
    context.logger.info(action)
    vote_id = action['block_id'].split('_')[-1]
    found_flag = False
    for i in GLOBAL_VOTES:
        if i.vote_id == vote_id:
            i.stop_vote()
            found_flag = True
            result_vote = i.median()
    if found_flag:
        if result_vote:
            context.issue_value = result_vote
            context.issue_key, jira_issue_id = action['value'].split('_')
            final_response = prepare_result_payload(context)
            if write_jira_issue(jira_issue_id, result_vote):
                context.respond(final_response)
        else:
            context.respond(
                {"text": "No votes yet, cannot complete", "epehmeral": "false", "replace_original": "false"})
    else:
        barking_response.update({
            "channel": body["channel"]["id"],
            "user": body['user']['id'],
            "text": ":warning: Нельзя завершить голосование, которое ещё не началось",
            "replace_original": False,
            "delete_original": False}
        )
        client.chat_postEphemeral(**barking_response)


@app.block_action(ID_OPTION)
def option_handler(context, body, action):
    context.ack()
    vote_id = action['block_id'].split('_')[-1]
    vote_value = action['selected_option']['value']
    user_id = body['user']['id']
    new_vote_flag = True
    for vote in GLOBAL_VOTES:
        if vote.vote_id == vote_id:
            vote.upsert_vote(user_id, vote_value)
            new_vote_flag = False
            context.logger.info('Vote updated')
            break
    if new_vote_flag:
        GLOBAL_VOTES.append(Vote(vote_id=vote_id, user_id=user_id, value=vote_value))
        context.logger.info('Vote created')
    # action is as follows:
    # {'action_id': 'option_select', 'block_id': 'opt_MSMYLp',
    # 'selected_option': {'text':
    # {'type': 'mrkdwn', 'text': ':five:', 'verbatim': False}, 'value': '5'},
    # 'type': 'radio_buttons', 'action_ts': '1637522838.388829'}


@app.block_action(ID_VOTE)
def vote_btn_handler(context, body, client, action):
    context.ack()
    vote_id = action['block_id'].split('_')[-1]
    response = {"channel": body["channel"]["id"]}
    possibly_ts = body['message'].get('thread_ts', None)
    if possibly_ts:
        response['thread_ts'] = possibly_ts
    found_flag = False
    for i in GLOBAL_VOTES:
        if i.vote_id == vote_id:
            found_flag = True
    if found_flag is False:
        # User did not choose the answer, but voted
        response.update({'text': ':warning: Нельзя проголосовать, не выбрав ничего',
                         'delete_original': False,
                         "replace_original": False,
                         "user": body['user']['id']
                         })
        client.chat_postEphemeral(**response)
    else:
        new_blocks = body['message']['blocks']
        existing_block_type = new_blocks[-2]['type']
        user_id_txt = f"<@{body['user']['id']}>"
        if existing_block_type == 'actions':
            new_blocks.append({
                "type": "context",
                "elements": [
                    {"type": "plain_text", "text": "Голосовали:"},
                    {"type": "mrkdwn", "text": user_id_txt}]
            })
            context.logger.info('This user has not voted before')
        if existing_block_type == 'context':
            # context already present, update
            found_flag = False
            for i in new_blocks[-2]['elements']:
                if i['type'] != "mrkdwn":
                    continue
                if i['text'] == user_id_txt:
                    found_flag = True
                    context.logger.info('This user has voted already')
                    break
            if found_flag is False:
                new_blocks[-2]['elements'].append({"type": "mrkdwn", "text": user_id_txt})
                context.logger.info('This user has not voted before')
        response.update({'blocks': new_blocks,
                         'text': "Ваш выбор учтён",
                         "ts": body["message"]["ts"]
                         })
        client.chat_update(**response)
        context.logger.info(existing_block_type)


@app.event({
    "type": "message",
    "subtype": "message_changed"
})
def message_change_handler():
    # for future development
    pass


def prepare_vote_payload(context):
    try:
        res = read_jira_issue(context.issue_key)
        context.logger.warn(res)
        parameters = {
            "task": context.issue_key,
            "description": res['fields']['description'] if res['fields']['description'] else None,
            "summary": res['fields']['summary'],
            "options_id": ID_OPTION,
            "send_id": ID_VOTE,
            "complete_id": ID_COMPLETE,
            "task_id": res['id']
        }
        blk = magic.load("vote_yml.j2", **parameters)
        issue = blk
        context.logger.debug(f"This is issue: {issue}")
    except urllib.error.HTTPError as e:
        issue = f"Sorry... This is the *Jira* error for {context.issue_key}: {e}"
    return issue


@app.event({"type": "message", "subtype": "message_deleted"})
def deletion_handler(context):
    context.logger.info("DELETED")
    return 200, {}


@app.event("reaction_removed")
def reaction_removed_handler(context, body):
    context.logger.info(body)
    return 200, {}


@app.event("app_mention")
def run_commands(context, body):
    outer = [block['elements'] for block in body['event']['blocks']][0]
    context.logger.info(outer)
    outer2 = [outer_element['elements'] for outer_element in outer][0]
    context.logger.info(outer2)
    tokens = [x for x in
              [CLEANSER_RE.sub('', block['text']) for block in outer2 if block['type'] == 'text'][0].split(' ') if x]
    # this is for the case when everything goes south -
    # spare tokenizing expression to switch to: body['event']['text'].split(' ')
    issue_key = None
    command = None
    parse_errors = []
    for token in tokens:
        if PREPARED_ISSUE_RE.match(token):
            context.issue_key = token
            continue
        if token in COMMANDS:
            if command:
                # >=2 commands here
                parse_errors.append(">=2 commands, refusing")
            else:
                command = token
                continue
        parse_errors.append(token)
    if parse_errors:
        text = f'Sorry, unexpected tokens: {",".join(parse_errors)}'
    else:
        text = f"Action {command} on issue {issue_key}"
    if command:
        if command == 'vote':
            vote_payload = prepare_vote_payload(context)
            possibly_ts = body['event'].get('thread_ts', None)
            if possibly_ts:
                vote_payload['thread_ts'] = possibly_ts
            send_result = context.say(vote_payload)
            context.logger.info(send_result)
    else:
        context.say(f"Got ya <@{body['event']['user']}>, this is how I see it:")
        context.say(f"{text}")


@app.event({"type": "message"})
def handle_message():
    # for future development
    pass


flask_app = Flask(__name__)
handler = SlackRequestHandler(app)


@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    return handler.handle(request)


# pip install -r requirements.txt
# export SLACK_SIGNING_SECRET=***
# export SLACK_BOT_TOKEN=xoxb-***
# FLASK_APP=app.py FLASK_ENV=development flask run -p 3000

# or this:
if __name__ == '__main__':
    load_jira_config()
    # configure_commands(COMMANDS)
    magic = J2()
    flask_app.run(debug=True)
