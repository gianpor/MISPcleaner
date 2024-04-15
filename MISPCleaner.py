from pymisp import PyMISP
from datetime import datetime, timedelta
from time import sleep
import json
import math
import requests
from cortex4py.api import Api
from cortex4py.query import *

misp_url = "INSERT_MISP_URL" #here need to be inserted the URL related to your MISP instance
misp_key = "INSERT_MISP_KEY" #here need to be inserted the key related to your MISP instance
misp_verifycert = False
cortex_api = Api('INSERT_CORTEX_URL', 'INSERT_CORTEX_KEY') #here need to be inserted the URL and key related to your Cortex instance
misp = PyMISP(misp_url, misp_key, misp_verifycert)

def check_sightings(attribute):
  attr_value = attribute['value']
  attr_type = attribute['type']
  if attr_type.startswith("ip"):
    attr_type = "ip"
  elif attr_type == 'md5' or attr_type.startswith("sha"):
    attr_type = "hash"
  if 'Sighting' in attribute:
    if len(attribute['Sighting']) >= 3:
      sightings = attribute['Sighting']
      num_sightings = len(sightings)
      sorted_sightings = sorted(sightings, key=lambda x: int(x['date_sighting']), reverse=True)
      type_count = sum(1 for sighting in sightings if sighting['type'] == 1)

      if type_count >= num_sightings * 0.50 + 1:
        num_to_select = math.ceil(num_sightings * 0.30)
        latest_sightings = sorted_sightings[:num_to_select]
        if all(sighting['type'] == 1 for sighting in latest_sightings):
          return True
        else:
          return check_osint(attr_value, attr_type)
      else:
          return check_osint(attr_value, attr_type)
  else:
    return check_osint(attr_value, attr_type)


def check_osint(attr_value, attr_type):
  analyzers_by_type = cortex_api.analyzers.get_by_type(attr_type)
  for analyzer in analyzers_by_type:
    print(analyzer.name, analyzer.dataTypeList)
    cortex_api.run_analyzer(analyzer.name, attr_type, 2, attr_value)
  query_not_term = Or(Eq('status', 'Waiting'), Eq('status', 'InProgress'))
  query_term = Or(Eq('status', 'Success'), Eq('status', 'Failure'))
  jobs_not_term = cortex_api.jobs.find_all(query_not_term)

  waiting_time = 0
  while len(jobs_not_term) != 0:
    sleep(15)
    waiting_time +=1
    jobs_not_term = cortex_api.jobs.find_all(query_not_term)
    if waiting_time == (3*len(jobs_not_term)):
      stucked_jobs = cortex_api.jobs.find_all(query_not_term)
      for stuck in stucked_jobs:
        cortex_api.jobs.delete(stuck.id)
  jobs_term = cortex_api.jobs.find_all(query_term)

  reports = []
  scores_reports = {}
  for job in jobs_term:
    report = cortex_api.jobs.get_report(job.id).report
    reports.append(report.get('summary', {}))
    cortex_api.jobs.delete(job.id)
  for report in reports:
    print("REPORT", report)
    taxonomy = report['taxonomies'][0]['level']
    namespace = report['taxonomies'][0]['namespace']
    print(taxonomy, namespace)
    scores_reports[namespace] = taxonomy

  analyzers_scores = {"VT" : 0.8, "AbuseIPDB" : 0.8, "Shodan" : 0.5}
  scores = {"malicious" : 1, "suspicious" : 0.5, "clean" : 0, "info" : 0}

  num = 0
  denom = 0
  for score in scores_reports.keys():
    num += analyzers_scores[score] * scores[scores_reports[score]]
    denom += analyzers_scores[score]
  w_avg = num / denom
  if w_avg > scores["suspicious"]:
    return True
  else:
    return False


if __name__ == "__main__":
  events = misp.search()
  two_w_ago = datetime.utcnow() - timedelta(days=15)
  for event in events:
    event_date = datetime.fromisoformat(event['Event']['date'])
    if event_date <= two_w_ago:
      misp.delete_event(event['Event']['uuid'])
    else:
      for attribute in event['Event']['Attribute']:
        if check_sightings(attribute) == True:
          misp.delete_attribute(attribute)