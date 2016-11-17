
#
# avalanche
# stix repacker
#
# recurse and convert all nested objects to references
# an accumulator (ax) is used to collect the output.
#
# all methods return new objects, inputs are unmodified
#

#
# todo:
# - verify relationships?  some may be missing in python-stix
# - may be useful to build a table of dangling idref leaf nodes
# - zero support for 'related_packages' in any nodes
# - can related_pacakges be embedded?  i think they can be :(

#
# notation:
#  ax - accumulator for concrete objects
#   o - api object
#   n - new object being created
#
# accumulator entries are in the format:
#  { stix_id : (shortname,apiobject) }
#

import sys
from copy import deepcopy

from repository_stix.ttp import TTP
from repository_stix.campaign import Campaign
from repository_stix.incident import Incident
from repository_stix.coa import CourseOfAction
from repository_stix.indicator import Indicator
from repository_stix.threat_actor import ThreatActor
from cybox.core.observable import Observable, ObservableComposition, Observables
from repository_stix.exploit_target import ExploitTarget
from repository_stix.core.stix_package import STIXPackage
from repository_stix.core.ttps import TTPs # weird, why the sesame street one

from repository_stix.utils.parser import EntityParser

OBJTAB = {
    'cam' : 'campaigns',
    'coa' : 'courses_of_action',
    'tgt' : 'exploit_targets',
    'inc' : 'incidents',
    'ind' : 'indicators',
    'obs' : 'observables',
    'act' : 'threat_actors',
    'ttp' : 'ttps',
}

# create "idref" objects from an id
def IdrefObservable(a):     return Observable    (id_=None,idref=a)
def IdrefIndicator(a):      return Indicator     (id_=None,idref=a)
def IdrefIncident(a):       return Incident      (id_=None,idref=a)
def IdrefCourseOfAction(a): return CourseOfAction(id_=None,idref=a)
def IdrefTTP(a):            return TTP           (id_=None,idref=a)
def IdrefThreatActor(a):    return ThreatActor   (id_=None,idref=a)
def IdrefExploitTarget(a):  return ExploitTarget (id_=None,idref=a)
def IdrefCampaign(a):       return Campaign      (id_=None,idref=a)


class Accumulator(object):

    def __init__(self):
        self.ax = {}

    def add(self,shortname,apiobj):
        assert isinstance(apiobj.id_,basestring)
        if apiobj.id_ in self.ax:
            raise Exception('Attempted to add duplicate id to accumulator, '+apiobj.id_)
        self.ax[apiobj.id_] = (shortname,apiobj)

    def list_by_type(self,shortname):
        return [ item[1] for id_,item in self.ax.iteritems() if item[0] == shortname ]

    def dump(self):
        #return { id_:(item[0],item[1]) for id_,item in self.ax.iteritems() }
        return self.ax


def flatten_pkg(src):

    n = deepcopy(src)

    if n.related_packages:
        raise Exception("related_packages unsupported")

    # remap and accumulate
    ax = Accumulator()
    for o in n.campaigns:               flatten_cam(o,ax)
    for o in n.courses_of_action:       flatten_coa(o,ax)
    for o in n.exploit_targets:         flatten_tgt(o,ax)
    for o in n.incidents:               flatten_inc(o,ax)
    for o in n.indicators:              flatten_ind(o,ax)
    for o in getattr(n.observables,'observables',[]): flatten_obs(o,ax)
    for o in n.threat_actors:           flatten_act(o,ax)
    for o in n.ttps:                    flatten_ttp(o,ax)

    # replace package lists with accumulator contents
    n.campaigns[:]         =              ax.list_by_type('cam')
    n.courses_of_action[:] =              ax.list_by_type('coa')
    n.exploit_targets[:]   =              ax.list_by_type('tgt')
    n.incidents[:]         =              ax.list_by_type('inc')
    n.indicators[:]        =              ax.list_by_type('ind')
    n.observables          = Observables( ax.list_by_type('obs') )
    n.threat_actors[:]     =              ax.list_by_type('act')
    n.ttps                 =        TTPs( ax.list_by_type('ttp') )

    return n


def unpack(src):
    """flatten and return a list of all objects"""

    n = deepcopy(src)

    if getattr(n,'related_packages',None):
        raise Exception("related_packages unsupported")

    # remap and accumulate
    ax = Accumulator()
    for o in n.campaigns:               flatten_cam(o,ax)
    for o in n.courses_of_action:       flatten_coa(o,ax)
    for o in n.exploit_targets:         flatten_tgt(o,ax)
    for o in n.incidents:               flatten_inc(o,ax)
    for o in n.indicators:              flatten_ind(o,ax)
    for o in getattr(n.observables,'observables',[]): flatten_obs(o,ax)
    for o in n.threat_actors:           flatten_act(o,ax)
    for o in n.ttps:                    flatten_ttp(o,ax)

    return ax.dump()


#--------------------------------------------------------------------
def flatten_obs(src,ax):
    n = deepcopy(src)

    if n.idref is not None: return n

    if n.observable_composition is not None:
        oblist = [ flatten_obs(sub,ax) for sub in n.observable_composition.observables ]
        n.observable_composition.observables[:] = oblist

    ax.add('obs',n)
    return IdrefObservable(n.id_)


#--------------------------------------------------------------------
def flatten_ind(src,ax):
    n = deepcopy(src)
    if n.idref is not None: return n

    if n.composite_indicator_expression:
        for i in xrange(len(n.composite_indicator_expression)):
            newind = flatten_ind(n.composite_indicator_expression[i],ax)
            n.composite_indicator_expression[i] = newind

    for o in n.indicated_ttps:
        o.item = flatten_ttp(o.item,ax)

    for o in n.suggested_coas:
        o.item = flatten_coa(o.item,ax)

    n.observables               = [ flatten_obs(o,ax) for o in n.observables ]
    n.related_indicators        = [ flatten_ind(o,ax) for o in n.related_indicators ]
    #n.related_campaigns        = [ flatten_cam(o,ax) for o in n.related_campaigns ] # not supported in python-stix?

    ax.add('ind',n)
    return IdrefIndicator(n.id_)


#--------------------------------------------------------------------
def flatten_inc(src,ax):
    n = deepcopy(src)
    if n.idref is not None: return n

    n.attributed_threat_actors  = [ flatten_act(o,ax) for o in n.attributed_threat_actors ]
    n.coa_taken                 = [ flatten_coa(o,ax) for o in n.coa_taken ]
    n.leveraged_ttps            = [ flatten_ttp(o,ax) for o in n.leveraged_ttps ]
    n.related_incidents         = [ flatten_inc(o,ax) for o in n.related_incidents ]
    n.related_indicators        = [ flatten_ind(o,ax) for o in n.related_indicators ]
    n.related_observables       = [ flatten_obs(o,ax) for o in n.related_observables ]
    # coa requested?
    # related threat actors?

    ax.add('inc',n)
    return IdrefIncident(n.id_)


#--------------------------------------------------------------------
def flatten_coa(src,ax):
    n = deepcopy(src)
    if n.idref is not None: return n

    if getattr(n,'related_packages',None):
        raise Exception("related_packages unsupported")

    if n.related_coas:
        n.related_coas              = [ flatten_coa(o,ax) for o in n.related_coas ]
    if n.parameter_observables:
        n.parameter_observables     = [ flatten_obs(o,ax) for o in n.parameter_observables ]

    ax.add('obs',n)
    return IdrefCourseOfAction(n.id_)


#--------------------------------------------------------------------
def flatten_ttp(src,ax):
    n = deepcopy(src)
    if n.idref is not None: return n

    n.exploit_targets           = [ flatten_tgt(o,ax) for o in n.exploit_targets ]
    for o in n.related_ttps: o.item = flatten_ttp(o.item,ax)

    ax.add('ttp',n)
    return IdrefTTP(n.id_)


#--------------------------------------------------------------------
def flatten_cam(src,ax):
    n = deepcopy(src)
    if n.idref is not None: return n

    if getattr(n,'related_packages',None):
        raise Exception("related_packages unsupported")

    # are these relationships correct? does python-stix have too many ?
    if n.associated_campaigns:
        n.associated_campaigns      = [ flatten_cam(o,ax) for o in n.associated_campaigns ]

    for at in n.attribution:
        for rta in at:
            rta.item = flatten_act(rta.item,ax)

    if n.related_incidents:
        n.related_incidents         = [ flatten_inc(o,ax) for o in n.related_incidents ]

    if n.related_indicators:
        n.related_indicators        = [ flatten_ind(o,ax) for o in n.related_indicators ]

    for o in n.related_ttps:
        o.item = flatten_ttp(o.item,ax)

    ax.add('cam',n)
    return IdrefCampaign(n.id_)


#--------------------------------------------------------------------
def flatten_act(src,ax):
    n = deepcopy(src)
    if n.idref is not None: return n

    if getattr(n,'related_packages',None):
        raise Exception("related_packages unsupported")

    if getattr(n,'associated_actors',None):
        for o in n.associated_actors:
            o.item = flatten_act(o.item,ax)

    if getattr(n,'associated_campaigns',None):
        for o in n.associated_campaigns:
            o.item = flatten_cam(o.item,ax)

    if getattr(n,'observed_ttps',None):
        for o in n.observed_ttps:
            o.item = flatten_ttp(o.item,ax)

    ax.add('act',n)
    return IdrefThreatActor(n.id_)


#--------------------------------------------------------------------
def flatten_tgt(src,ax):
    n = deepcopy(src)
    if n.idref is not None: return n

    if getattr(n,'related_packages',None):
        raise Exception("related_packages unsupported")

    n.potential_coas            = [ flatten_coa(o,ax) for o in n.potential_coas ]
    n.related_exploit_targets   = [ flatten_tgt(o,ax) for o in n.related_exploit_targets ]

    ax.add('tgt',n)
    return IdrefExploitTarget(n.id_)


def main():

    if len(sys.argv) != 3:
        print 'usage: %s <in.xml> <out.xml>' % sys.argv[0]
        sys.exit(1)

    with open(sys.argv[1],'r') as fd_input:
        with open(sys.argv[2],'w') as fd_output:
            srcpkg = EntityParser().parse_xml(fd_input,check_version=False)
            newpkg = flatten_pkg(srcpkg)
            fd_output.write(newpkg.to_xml())

    sys.exit(0)

if __name__ == '__main__':
    main()

