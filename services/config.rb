coreo_aws_rule "cloudwatchlogs-inventory" do
  action :define
  service :cloudwatchlogs
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "CloudwatchLogs Inventory"
  description "This rule performs an inventory on all cloudwatchlogs objects in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["log_groups"]
  audit_objects ["object.log_groups.log_group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.log_groups.log_group_name"
end

coreo_uni_util_variables "cloudwatchlogs-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.cloudwatchlogs-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.cloudwatchlogs-planwide.plan_name' => 'PLAN::name'},
                {'GLOBAL::number_violations' => '0'}
            ])
end

coreo_aws_rule_runner "advise-cloudwatchlogs" do
  action :run
  rules ${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_LIST}
  service :cloudwatchlogs
  regions ${AUDIT_AWS_CLOUDWATCHLOGS_REGIONS}
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-cloudwatchlogs" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-9"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }
           ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-cloudwatchlogs.report}'
  function <<-EOH

function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading suppression.yaml file: " , e);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log("Error reading table.yaml file: ", e);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));
  
  let alertListToJSON = "${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_LIST}";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}


setTableAndSuppression();

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_CLOUDWATCHLOGS_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_CLOUDWATCHLOGS_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_CLOUDWATCHLOGS_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const SETTINGS = { NO_OWNER_EMAIL, OWNER_TAG,
    ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditCLOUDWATCHLOGS = new CloudCoreoJSRunner(JSON_INPUT, SETTINGS);
const letters = AuditCLOUDWATCHLOGS.getLetters();

const JSONReportAfterGeneratingSuppression = AuditCLOUDWATCHLOGS.getSortedJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(JSONReportAfterGeneratingSuppression));

callback(letters);
  EOH
end

coreo_uni_util_jsrunner "tags-rollup-cloudwatchlogs" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-cloudwatchlogs.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_variables "cloudwatchlogs-update-planwide" do
  action :set
  variables([
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-cloudwatchlogs.table'}
            ])
end

coreo_uni_util_notify "advise-cloudwatchlogs-to-tag-values" do
  action((("${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-cloudwatchlogs.return'
end

coreo_uni_util_notify "advise-cloudwatchlogs-rollup" do
  action((("${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_CLOUDWATCHLOGS_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_CLOUDWATCHLOGS_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_CLOUDWATCHLOGS_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-cloudwatchlogs.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_RECIPIENT}', :subject => 'CloudCoreo cloudwatchlogs rule results on PLAN::stack_name :: PLAN::name'
  })
end
