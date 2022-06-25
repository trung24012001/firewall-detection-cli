from mimetypes import init


class RuleRelationship:
  def __init__(self):
    self.rules = []
    self.ip_src = []
    self.ip_dst = []
    self.port_src = []
    self.port_dst = []
    self.protocol = []
  
  def get_rules(self):
    return None