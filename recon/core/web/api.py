from flask import Blueprint, current_app, request, abort
from flask_restful import Resource, Api
from recon.core.web import recon, tasks
from recon.core.web.utils import columnize
from recon.core.web.constants import EXPORTS, REPORTS
import io
import os
import re
import sys
import threading
import uuid


resources = Blueprint('resources', __name__, url_prefix='/api')
api = Api()
api.init_app(resources)


class TaskList(Resource):

    def get(self):
        '''
        Gets all tasks for the current workspace
        ---
        responses:
            200:
                description: List of tasks
                schema:
                    properties:
                        tasks:
                            type: array
                            items:
                                $ref: '#/definitions/Task'
                    required:
                    - tasks
        '''
        return {
            'tasks': tasks.get_tasks(),
        }

    def post(self):
        '''
        Runs a module as a background task
        ---
        parameters:
          - name: body
            in: body
            description: Object containing the path of the module to run
            schema:
                properties:
                    path:
                        type: string
                required:
                - path
        responses:
            201:
                description: Object containing the ID of the created task
                schema:
                    properties:
                        task:
                            type: string
                    required:
                    - task
        '''
        path = request.json.get('path')
        if not path or path not in recon._loaded_modules:
            abort(404)
        tid = str(uuid.uuid4())
        tasks.add_task(tid, 'queued')
        try:
            job = current_app.task_queue.enqueue('recon.core.tasks.run_module', current_app.config['WORKSPACE'], path, job_id=tid)
            tasks.update_task(tid, status='running')
            return {
                'task': tid,
                'queued': 'redis',
            }, 201
        except Exception:
            def worker():
                buf = io.StringIO()
                old_out = sys.stdout
                sys.stdout = buf
                results = {}
                try:
                    tasks.update_task(tid, status='running')
                    mod = recon._loaded_modules[path]
                    mod.do_run(None)
                    results['summary'] = getattr(mod, '_summary_counts', {})
                    results['output'] = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', buf.getvalue())
                    tasks.update_task(tid, status='finished', result=results)
                except Exception as e:
                    results['error'] = {'type': type(e).__name__, 'message': str(e)}
                    results['output'] = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', buf.getvalue())
                    tasks.update_task(tid, status='failed', result=results)
                finally:
                    sys.stdout = old_out
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            return {
                'task': tid,
                'queued': 'thread',
            }, 201

api.add_resource(TaskList, '/tasks/')


class TaskInst(Resource):

    def get(self, tid):
        '''
        Gets the specified task
        ---
        parameters:
          - name: tid
            in: path
            description: ID of the target task
            required: true
            type: string
          - name: live
            in: query
            description: If set, queries the Redis queue instead of the database
            required: false
            type: string
        responses:
            200:
                description: Object containing the specified task
                schema:
                    $ref: '#/definitions/Task'
        '''
        if tid not in tasks.get_ids():
            abort(404)
        # process requests for the rq version of the task
        if request.args.get('live'):
            # baseline task object
            task = {
                'id': tid,
                'status': 'unknown',
                'result': None,
            }
            job = current_app.task_queue.fetch_job(tid)
            if job:
                task['status'] = job.get_status()
                task['result'] = job.result
        else:
            task = tasks.get_task(tid)
        return task

api.add_resource(TaskInst, '/tasks/<string:tid>')


class ModuleList(Resource):

    def get(self):
        '''
        Gets all module names from the framework
        ---
        responses:
            200:
                description: List of module names
                schema:
                    properties:
                        modules:
                            type: array
                            items:
                                type: string
                    required:
                    - modules
        '''
        return {
            'modules': sorted(list(recon._loaded_modules.keys())),
        }

api.add_resource(ModuleList, '/modules/')


class ModuleInst(Resource):

    def get(self, module):
        '''
        Gets information about the specified module
        ---
        parameters:
          - name: module
            in: path
            description: Path of the target module
            required: true
            type: string
        responses:
            200:
                description: Object containing the specified module's information
                schema:
                    $ref: '#/definitions/Module'
        '''
        module = recon._loaded_modules.get(module)
        if module is None:
            abort(404)
        meta = {k: v for k, v in module.meta.items()}
        # provide options with more context
        options = module.options.serialize()
        if options:
            meta['options'] = options
        return meta

    def patch(self, module):
        '''
        Updates the specified module
        Options are the only modifiable property of a module object.
        ---
        parameters:
          - name: module
            in: path
            description: Name of the target module
            required: true
            type: string
          - name: body
            in: body
            description: Object containing the options to update
            schema:
                properties:
                    options:
                        type: array
                        items:
                            type: object
                            properties:
                                name:
                                    type: string
                                value:
                                    type: string
                            required:
                            - name
                            - value
                required:
                - options
        responses:
            200:
                description: Object containing the modified module's information
                schema:
                    $ref: '#/definitions/Module'
        '''
        module = recon._loaded_modules.get(module)
        if module is None:
            abort(404)
        options = request.json.get('options')
        # process options
        if options:
            for option in options:
                name = option.get('name')
                value = option.get('value')
                if name and value and name in module.options:
                    module.options[name] = value
                    module._save_config(name)
        return self.get(module._modulename)

api.add_resource(ModuleInst, '/modules/<path:module>')


class WorkspaceList(Resource):

    def get(self):
        '''
        Gets all workspace names from the framework
        ---
        responses:
            200:
                description: List of workspace names
                schema:
                    properties:
                        workspaces:
                            type: array
                            items:
                                type: string
                    required:
                    - workspaces
        '''
        return {
            'workspaces': sorted(recon._get_workspaces()),
        }

    def post(self):
        '''
        Creates a new workspace
        '''
        name = request.json.get('name') if request.is_json else None
        if not name or not isinstance(name, str):
            abort(400, description="Valid workspace 'name' is required.")
        name = name.strip()
        if not name or not re.match(r'^[a-zA-Z0-9_\-]+$', name):
            abort(400, description="Workspace name must contain only alphanumeric characters, underscores, or hyphens.")
        if recon._init_workspace(name):
            tasks.__init__(recon)
            current_app.config['WORKSPACE'] = name
            return {
                'message': f"Workspace '{name}' created and activated.",
                'workspace': name,
            }, 201
        abort(500, description="Failed to create workspace.")

api.add_resource(WorkspaceList, '/workspaces/')


class WorkspaceInst(Resource):

    def get(self, workspace):
        '''
        Gets information about the specified workspace
        Only returns options for the active workspace.
        ---
        parameters:
          - name: workspace
            in: path
            description: Name of the target workspace
            required: true
            type: string
        responses:
            200:
                description: Object containing the specified workspace's information
                schema:
                    $ref: '#/definitions/Workspace'
        '''
        if workspace not in recon._get_workspaces():
            abort(404)
        status = 'inactive'
        options = []
        if workspace == current_app.config['WORKSPACE']:
            status = 'active'
            options = recon.options.serialize()
        return {
            'name': workspace,
            'status': status,
            'options': options,
        }

    def patch(self, workspace):
        '''
        Updates the specified workspace
        Activating a workspace deactivates the currently activated workspace, and only the active workspace's options can be modified.
        ---
        parameters:
          - name: workspace
            in: path
            description: Name of the target workspace
            required: true
            type: string
          - name: body
            in: body
            description: Object containing the properties to update
            schema:
                properties:
                    status:
                        type: string
                    options:
                        type: array
                        items:
                            type: object
                            properties:
                                name:
                                    type: string
                                value:
                                    type: string
                            required:
                            - name
                            - value
        responses:
            200:
                description: Object containing the modified workspace's information
                schema:
                    $ref: '#/definitions/Workspace'
        '''
        if workspace not in recon._get_workspaces():
            abort(404)
        status = request.json.get('status')
        options = request.json.get('options')
        # process status
        if status:
            # ignore everything but a request to activate
            if status == 'active':
                # only continue if the workspace is not already active
                if current_app.config['WORKSPACE'] != workspace:
                    # re-initialize the workspace and tasks object
                    recon._init_workspace(workspace)
                    tasks.__init__(recon)
                    # add the workspace name the to global object
                    current_app.config['WORKSPACE'] = workspace
                    print((f" * Workspace initialized: {workspace}"))
        # process options
        if options:
            # only continue if the workspace is active
            if current_app.config['WORKSPACE'] == workspace:
                for option in options:
                    name = option.get('name')
                    value = option.get('value')
                    if name and value and name in recon.options:
                        recon.options[name] = value
                        recon._save_config(name)
        return self.get(workspace)

    def delete(self, workspace):
        '''
        Deletes the specified workspace
        '''
        if workspace not in recon._get_workspaces():
            abort(404, description="Workspace not found.")
        if workspace == 'default':
            abort(400, description="Cannot delete the 'default' workspace.")
        if recon.remove_workspace(workspace):
            current_app.config['WORKSPACE'] = os.path.basename(recon.workspace)
            tasks.__init__(recon)
            return {
                'message': f"Workspace '{workspace}' removed.",
                'current_workspace': current_app.config['WORKSPACE']
            }
        abort(500, description="Failed to remove workspace.")

api.add_resource(WorkspaceInst, '/workspaces/<string:workspace>')


class DashboardInst(Resource):

    def get(self):
        '''
        Gets summary information about the current workspace
        ---
        responses:
            200:
                description: Object containing the summary information
                schema:
                    $ref: '#/definitions/Dashboard'
        '''
        # build the activity object
        dashboard = recon.query('SELECT * FROM dashboard', include_header=True)
        columns = dashboard.pop(0)
        activity = columnize(columns, dashboard)
        # build the records object
        records = []
        tables = recon.get_tables()
        for table in tables:
            count = recon.query(f"SELECT COUNT(*) AS 'COUNT' FROM {table}")
            records.append({'name': table, 'count':count[0][0]})
        # sort both lists in descending order
        records.sort(key=lambda r: r['count'], reverse=True)
        activity.sort(key=lambda m: m['runs'], reverse=True)
        return {
            'workspace': current_app.config['WORKSPACE'],
            'records': records,
            'activity': activity,
        }

api.add_resource(DashboardInst, '/dashboard')


class ReportList(Resource):

    def get(self):
        '''
        Gets all report types from the framework
        ---
        responses:
            200:
                description: List of report types
                schema:
                    properties:
                        reports:
                            type: array
                            items:
                                type: string
                    required:
                    - reports
        '''
        return {
            'reports': sorted(list(REPORTS.keys())),
        }

api.add_resource(ReportList, '/reports/')


class ReportInst(Resource):

    def get(self, report):
        '''
        Runs the specified report for the current workspace
        ---
        parameters:
          - name: report
            in: path
            description: Name of the report type
            required: true
            type: string
        '''
        if report not in REPORTS:
            abort(404)
        return REPORTS[report]()

api.add_resource(ReportInst, '/reports/<string:report>')


class TableList(Resource):

    def get(self):
        '''
        Gets all table names for the current workspace
        ---
        responses:
            200:
                description: Object containing the list of tables names
                schema:
                    properties:
                        workspace:
                            type: string
                        tables:
                            type: array
                            items:
                                type: string
                    required:
                    - workspace
                    - tables
        '''
        return {
            'workspace': current_app.config['WORKSPACE'],
            'tables': sorted(recon.get_tables()),
        }

api.add_resource(TableList, '/tables/')


class TableInst(Resource):

    def get(self, table):
        '''
        Dumps the contents of the specified table
        ---
        parameters:
          - name: table
            in: path
            description: Name of the target table
            required: true
            type: string
          - name: format
            in: query
            description: Export type
            required: false
            type: string
        responses:
            200:
                description: Object containing the specified table's contents
                schema:
                    $ref: '#/definitions/Table'
        '''
        if table not in recon.get_tables():
            abort(404)
        # filter rows for columns if needed (whitelist validated against schema)
        table_cols = [c[1] for c in recon.query(f'PRAGMA table_info("{table}")')]
        columns_arg = request.values.get('columns')
        if columns_arg:
            req_cols = [c.strip() for c in columns_arg.split(',') if c.strip()]
            valid_cols = [c for c in req_cols if c in table_cols]
            if not valid_cols:
                abort(400, description="Invalid column selection.")
            safe_cols = ", ".join(f'"{c}"' for c in valid_cols)
            rows = recon.query(f'SELECT rowid, {safe_cols} FROM "{table}"', include_header=True)
        else:
            rows = recon.query(f'SELECT rowid, * FROM "{table}"', include_header=True)
        columns = rows.pop(0)
        rows = columnize(columns, rows)
        # dynamically determine and call export function
        _format = request.args.get('format')
        if _format and _format in EXPORTS:
            # any required serialization is handled at the exporter level
            export_rows = [{k: v for k, v in r.items() if k != 'rowid'} for r in rows]
            return EXPORTS[_format](rows=export_rows)
        return {
            'workspace': current_app.config['WORKSPACE'],
            'table': table,
            'columns': columns,
            'rows': rows,
        }

    def post(self, table):
        '''
        Inserts a record into the specified table
        '''
        if table not in recon.get_tables():
            abort(404, description="Table not found.")
        data = request.json
        if not data or not isinstance(data, dict):
            abort(400, description="JSON object of column-value pairs required.")
        table_cols = [c[1] for c in recon.query(f'PRAGMA table_info("{table}")')]
        cleaned = {k: v for k, v in data.items() if k in table_cols and k != 'rowid' and v is not None and str(v).strip() != ''}
        unique_cols = [k for k in cleaned.keys() if k != 'notes']
        rowcount = recon.insert(table, cleaned, unique_columns=unique_cols)
        return {
            'message': f"Inserted into '{table}'.",
            'affected_rows': rowcount,
            'data': cleaned
        }, 201

    def delete(self, table):
        '''
        Deletes a row by rowid or truncates the table
        '''
        if table not in recon.get_tables():
            abort(404, description="Table not found.")
        rowid = request.args.get('rowid') or (request.json.get('rowid') if request.is_json and request.json else None)
        if rowid:
            try:
                rowid = int(rowid)
            except (ValueError, TypeError):
                abort(400, description="Invalid rowid; must be an integer.")
            recon.query(f'DELETE FROM "{table}" WHERE rowid = ?', (rowid,))
            return {'message': f"Row {rowid} deleted from '{table}'."}
        else:
            recon.query(f'DELETE FROM "{table}"')
            return {'message': f"Table '{table}' cleared."}

api.add_resource(TableInst, '/tables/<string:table>')


class ModuleRun(Resource):

    def post(self, module):
        '''
        Runs the specified module directly and returns logs and summary
        '''
        if module not in recon._loaded_modules:
            abort(404, description="Module not found.")
        mod = recon._loaded_modules[module]
        data = request.json or {}
        options = data.get('options') or []
        for opt in options:
            name = opt.get('name')
            val = opt.get('value')
            if name and name in mod.options:
                mod.options[name] = val
                mod._save_config(name)
        
        buf = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buf
        status = 'finished'
        error = None
        try:
            mod.do_run(None)
        except Exception as e:
            status = 'failed'
            error = str(e)
        finally:
            sys.stdout = old_stdout

        output = buf.getvalue()
        clean_output = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', output)
        summary = getattr(mod, '_summary_counts', {})
        return {
            'module': module,
            'status': status,
            'error': error,
            'summary': summary,
            'output': clean_output
        }

api.add_resource(ModuleRun, '/modules/<path:module>/run')


class KeyList(Resource):

    def get(self):
        '''
        Gets all third-party API keys (with secret values masked)
        '''
        rows = recon._query_keys('SELECT name, value FROM keys')
        return {
            'keys': [
                {
                    'name': r[0],
                    'is_set': bool(r[1]),
                    'masked_value': f"{r[1][:4]}••••••••" if r[1] and len(r[1]) > 4 else ("••••" if r[1] else "")
                }
                for r in sorted(rows)
            ]
        }

    def post(self):
        '''
        Adds or updates an API key
        '''
        data = request.json or {}
        name = data.get('name')
        value = data.get('value', '')
        if not name or not isinstance(name, str):
            abort(400, description="Valid key name is required.")
        name = name.strip()
        if not re.match(r'^[a-zA-Z0-9_]+$', name):
            abort(400, description="Key name must be alphanumeric with underscores.")
        recon.add_key(name, value.strip())
        return {'message': f"Key '{name}' updated.", 'name': name}, 201

api.add_resource(KeyList, '/keys/')


class KeyInst(Resource):

    def delete(self, name):
        '''
        Removes an API key
        '''
        if recon.get_key(name):
            recon.remove_key(name)
            return {'message': f"Key '{name}' removed."}
        abort(404, description="Key not found.")

api.add_resource(KeyInst, '/keys/<string:name>')


class GlobalOptions(Resource):

    def get(self):
        '''
        Gets global framework options
        '''
        return {'options': recon.options.serialize()}

    def patch(self):
        '''
        Updates global framework options
        '''
        options = (request.json or {}).get('options') or []
        for opt in options:
            name = opt.get('name')
            val = opt.get('value')
            if name and name in recon.options:
                recon.options[name] = val
                recon._save_config(name)
        return {'options': recon.options.serialize()}

api.add_resource(GlobalOptions, '/options/')


class ExportList(Resource):

    def get(self):
        '''
        Gets all export types from the framework
        ---
        responses:
            200:
                description: List of export types
                schema:
                    properties:
                        exports:
                            type: array
                            items:
                                type: string
                    required:
                    - exports
        '''
        return {
            'exports': sorted(list(EXPORTS.keys())),
        }

api.add_resource(ExportList, '/exports')
