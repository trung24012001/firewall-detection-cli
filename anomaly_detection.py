class AnomalyDetection:
  def __init__(self) -> None:
    pass

  def normalize_anomaly(anomaly, fields):
    anomaly['norm'] = {}
    for field in fields:
        rule_a = anomaly['rule_a']
        rule_b = anomaly['rule_b']
        if rule_a['policy'] == rule_b['policy']:
            anomaly['norm']['policy'] = 1
            return anomaly
        anomaly['norm']['policy'] = 0
        if np.array_equal(rule_a[field], rule_b[field]):
            anomaly['norm'][field] = 'S'
        elif '*' in rule_a[field]:
            anomaly['norm'][field] = 'X'
        elif '*' in rule_b[field]:
            anomaly['norm'][field] = 'Z'
        elif (rule_a[field][0] in rule_b[field] and
                rule_a[field][-1] in rule_b[field]):
            anomaly['norm'][field] = 'Z'
        elif (rule_b[field][0] in rule_a[field] and
              rule_b[field][-1] in rule_a[field]):
            anomaly['norm'][field] = 'X'
        else:
            anomaly['norm'][field] = 'Y'

    return True
  
  def classify_anomaly(norm, fields):
    shadow = 0
    general = 0
    if norm['policy'] == 1:
        return 'redundancy'
    for field in fields:
        if norm[field] == 'X':
            shadow += 1
        elif norm[field] == 'Z':
            general += 1
        elif norm[field] == 'S':
            shadow += 1
            general += 1
    if shadow == len(fields):
        return 'shadowing'
    if general == len(fields):
        return 'generalization'
    return 'correlation'

  def analytics(anomalies):
      result = {
          "shadowing": 0,
          "generalization": 0,
          "correlation": 0,
          "redundancy": 0,
      }
      for anomaly in anomalies:
          type = anomaly['anomaly_type']
          if result.get(type) == None:
              continue
          result[type] += 1
      return result


  def format_anomaly(anomaly):
      fields = ['ip_src', 'ip_dst', 'port_src', 'port_dst', 'protocol']

      normalize_anomaly(anomaly, fields)
      anomaly['anomaly_type'] = classify_anomaly(
          norm=anomaly['norm'], fields=fields)
      # this comment is bugggg unknown why????
      # decompose.recompose(
      #     [anomaly['rule_a'], anomaly['rule_b']], fields)
      return anomaly



  def raw_detect_anomaly(ruleset):
      decompose.decompose(ruleset)
      pair_list = algorithm_detection(ruleset)
      anomalies = list(map(format_anomaly, pair_list))
      return {
          "anomalies":  anomalies,
          "analytics": analytics(anomalies)
      }


  def algorithm_detection(ruleset):
      pair_list = []
      len_ruleset = len(ruleset)
      for i in range(len_ruleset - 1):
          for j in range(i + 1, len_ruleset):
              if compare_rule(ruleset[i], ruleset[j]):
                  pair_list.append({
                      'id':  '-'.join(str(x) for x in [ruleset[i]['handle'], ruleset[j]['handle']]),
                      'rule_a': ruleset[i],
                      'rule_b': ruleset[j]
                  })
      return pair_list


  def compare_rule(rule_1, rule_2):
      fields = ['family', 'table', 'chain', 'hook', 'ip_src',
                'ip_dst', 'port_src', 'port_dst', 'protocol']

      for field in fields:
          if not match_property(rule_1[field], rule_2[field]):
              return False

      return True


  def match_property(prop_1, prop_2):
      if type(prop_1) == str:
          if prop_1 == prop_2:
              return True
          else:
              return False

      if '*' in [*prop_1, *prop_2]:
          return True
      for p in prop_1:
          if p in prop_2:
              return True

      return False
