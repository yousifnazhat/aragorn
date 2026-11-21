"""Only mock roots, proc subjects, directory listings, socket objects and clocks."""
from contextlib import ExitStack
from copy import deepcopy
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from aragorn import pi_core_owned_socket_directories as s


def sample_socket_edge(worker_uid=1001, worker_gid=1002, *, opened_boottime_ns=1000, closed_boottime_ns=1010,
                       manager_pid=123, manager_start_ticks=45, boot_id="12345678-1234-4234-8234-123456789abc",
                       time_namespace_inode=901):
    def obj(ino, mode, gid):
        v=dict(dev="0:50", ino=ino, mnt_id=29, mode=mode, uid=0, gid=gid,
               nlink=1 if stat.S_ISSOCK(mode) else 2)
        if stat.S_ISSOCK(mode): v.update(size=0, mtime_ns=9876, ctime_ns=9877)
        return v
    base="/run/aragorn-pi-bootstrap"
    dirs={}
    for role,parent,name,i,j,l in (("request","requests","request.sock",401,402,501),
                                   ("provider","provider","provider.sock",403,404,502)):
        dirs[role]=dict(path=base+"/"+parent,names=[name],object=obj(i,stat.S_IFDIR|0o711,worker_gid),
             endpoint=dict(path=base+"/"+parent+"/"+name,object=obj(j,stat.S_IFSOCK|0o660,worker_gid)),
             listener_handle=dict(dev="0:9",ino=l))
    return dict(schema="aragorn/pi-core-owned-socket-directories/v1", worker_uid=worker_uid,worker_gid=worker_gid,
                bootstrap=dict(path=base,object=obj(400,stat.S_IFDIR|0o755,0)), directories=dirs,boot_id=boot_id,
                time_namespace_inode=time_namespace_inode,opened_boottime_ns=opened_boottime_ns,
                closed_boottime_ns=closed_boottime_ns,manager=dict(pid=manager_pid,start_ticks=manager_start_ticks,
                uid=0,gid=0,mount_namespace=111,user_namespace=222))


class Listener:
    family, sock_type = s.socket.AF_UNIX, s.socket.SOCK_STREAM
    def __init__(self,fd):
        self.fd, self.type=fd,self.sock_type
    def fileno(self): return self.fd


class Kernel:
    def __init__(self):
        self.expected=sample_socket_edge()
        self.owners = []
        self.plan=SimpleNamespace(worker_uid=1001,worker_gid=1002)
        self.own=s.native._Owned(self.plan,run_fd=1,directory_fd=2,request_dispatch_active=True,
                                 provider_dispatch_active=True,listener=Listener(30))
        self.req=object.__new__(s.request.PiNativeRequestDispatch)
        self.prov=object.__new__(s.provider.PiNativeProviderDispatch)
        self.own._pi_request_dispatch,self.own._pi_provider_dispatch=self.req,self.prov
        self.prov._seal,self.prov._plan=s.provider._SEAL,self.plan
        self.objs={2:self.expected["bootstrap"]["object"], 1:dict(self.expected["bootstrap"]["object"],ino=399)}
        self.names={2:["bootstrap.sock","provider","requests"],3:["request.sock"],4:["provider.sock"]}
        self.opened=[]
        for role,df,nf,lf,d in (("request",3,5,31,self.req),("provider",4,6,32,self.prov)):
            row=self.expected["directories"][role]
            self.objs[df],self.objs[nf]=row["object"],row["endpoint"]["object"]
            d.owned,d.active,d.created,d.closed,d.deadline=self.own,True,True,False,80
            d.listener,d.directory_fd=Listener(lf),df
            d._ownership=lambda role=role:self.owners.append(role)
        self.own.directory_identity=s.broker._directory_identity(self.stat(2))
        for d,df,nf in ((self.req,3,5),(self.prov,4,6)):
            d.directory_identity=s.broker._directory_identity(self.stat(df))
            d.socket_identity=s.broker._file_identity(self.stat(nf))
        self.ns=self.expected["time_namespace_inode"]

    def stat(self, fd):
        if fd in (30,31,32):
            return SimpleNamespace(st_mode=stat.S_IFSOCK,st_dev=os.makedev(0,9),st_ino=fd+470)
        o=self.objs[fd]
        maj,minor=map(int,o["dev"].split(":"))
        return SimpleNamespace(st_mode=o["mode"],st_dev=os.makedev(maj,minor),st_ino=o["ino"],st_uid=o["uid"],
                st_gid=o["gid"],st_nlink=o["nlink"],st_size=o.get("size",0),st_mtime_ns=o.get("mtime_ns",0),
                st_ctime_ns=o.get("ctime_ns",0))

    def pin(self,st,parent,name,*,directory=False):
        self.opened.append((parent,name,directory))
        return {(90,"run",True):1,(1,"aragorn-pi-bootstrap",True):2,(2,"requests",True):3,(2,"provider",True):4,
                (3,"request.sock",False):5,(4,"provider.sock",False):6}[parent,name,directory]

    def enter(self,st):
        st.enter_context(patch.object(s,"socket",SimpleNamespace(socket=Listener,AF_UNIX=Listener.family,
                                                                SOCK_STREAM=Listener.sock_type)))
        st.enter_context(patch.object(s.kernel,"_platform"))
        st.enter_context(patch.object(s.kernel,"_check"))
        st.enter_context(patch.object(s,"_tick",side_effect=[1000,1010]))
        st.enter_context(patch.object(s.request,"_plan",side_effect=lambda o,d:o.plan))
        st.enter_context(patch.object(s.os,"fstat",side_effect=self.stat))
        st.enter_context(patch.object(s.kernel,"_pin",side_effect=self.pin))
        st.enter_context(patch.object(s.kernel,"_filesystem",side_effect=lambda fd:
                                     0x534f434b if fd in (30,31,32) else 0x01021994))
        st.enter_context(patch.object(s.kernel,"_stat",side_effect=lambda fd,owner:
                                     {k:v for k,v in self.objs[fd].items() if k not in ("nlink","size","mtime_ns","ctime_ns")}))
        def names(fd,d,l):
            assert len(self.names[fd]) <= l and d == 70
            return self.names[fd].copy()
        st.enter_context(patch.object(s.kernel,"_names",side_effect=names))
        st.enter_context(patch.object(s,"_context",side_effect=lambda _,d:(
            (self.expected["manager"].copy(),self.expected["boot_id"],self.ns),("held","caller"),90)))

    def capture(self):
        with ExitStack() as st:
            self.enter(st)
            return s.capture_owned_socket_directories(self.own,self.req,self.prov,deadline=70)


class SocketDirectories(unittest.TestCase):
    def test_real_owner_instances_are_bracketed_and_independent_samples_are_sanitized(self):
        k=Kernel()
        self.assertEqual(k.capture(),k.expected)
        self.assertEqual(k.owners,["request","provider"]*2)
        self.assertEqual(k.opened.count((3,"request.sock",False)),2)
        self.assertEqual(k.opened.count((4,"provider.sock",False)),2)
        self.assertNotIn((3,"provider.sock",False),k.opened)
        stopped=sample_socket_edge(opened_boottime_ns=1050,closed_boottime_ns=1060)
        self.assertEqual(s.verify_owned_socket_directories(k.expected,stopped,worker_uid=1001,worker_gid=1002),
                         dict(manager_socket_membership_observed=True,worker_lookup_observed=False,
                              worker_listing_observed=False,listener_readiness_observed=False,phase3_exit_eligible=False))

    def test_rejects_owner_substitution_deadline_and_inactive_handles_before_listing(self):
        for target,field,value in (("own","request_dispatch_active",False),("own","_pi_provider_dispatch",None),
                ("own","_pi_request_dispatch",None),("req","closed",True),("req","active",False),
                ("req","created",False),("req","directory_fd",2),("req","directory_identity",()),
                ("req","owned",None),("req","deadline",69),("prov","deadline",float("nan")),
                ("prov","_plan",None),("prov","_seal",object()),("prov","listener",None),
                ("prov","listener",Listener(31)),("prov","listener",Listener(-1))):
            k=Kernel()
            setattr(getattr(k,target),field,value)
            with self.subTest(target=target,field=field,value=value),self.assertRaises(ValueError):
                k.capture()
            self.assertFalse(k.opened)

    def test_checks_socket_type_nlink_permissions_names_and_named_held_identities(self):
        for fd,changes in ((3,{"mode":stat.S_IFDIR|0o755}),(5,{"mode":stat.S_IFREG|0o660}),
                (6,{"nlink":2}),(4,{"gid":0}),(4,{"ino":401}),(6,{"uid":1001}),
                (4,{"mnt_id":30}),(3,{"dev":"0:51"}),(1,{"uid":2})):
            k=Kernel()
            k.objs[fd].update(changes)
            with self.subTest(fd=fd,change=changes),self.assertRaises(ValueError):
                k.capture()
        for fd,listing in ((3,[]),(4,["request.sock"]),(2,["provider","requests"])):
            k=Kernel()
            k.names[fd]=listing
            with self.subTest(fd=fd),self.assertRaises(ValueError):
                k.capture()
        k=Kernel()
        k.prov.socket_identity=k.req.socket_identity
        with self.assertRaises(ValueError): k.capture()

    def test_guard_mutation_and_manager_changes_fail_before_edge_return(self):
        k=Kernel()
        def guard():
            k.owners.append("provider")
            if len(k.owners)==4: k.req.deadline=69
        k.prov._ownership=guard
        with self.assertRaises(ValueError): k.capture()
        k=Kernel()
        def clock_swap():
            k.owners.append("provider")
            k.ns=777
        k.prov._ownership=clock_swap
        with self.assertRaises(ValueError): k.capture()

    def test_pure_replay_denies_role_splice_mount_aliases_socket_substitution_and_fabricated_coverage(self):
        before=sample_socket_edge()
        for field,val in (("path","/run/other"),("names",[]),("names",["request.sock","x"]),
                          ("worker_opened",True),("listener_handle",{"dev":"0:50","ino":501})):
            a,b=deepcopy(before),sample_socket_edge(opened_boottime_ns=1015,closed_boottime_ns=1020)
            for record in (a,b): record["directories"]["request"][field]=val
            with self.subTest(field=field), self.assertRaises(ValueError):
                s.verify_owned_socket_directories(a,b,worker_uid=1001,worker_gid=1002)
        for key,value in (("dev","0:7"),("ino",400),("mode",stat.S_IFSOCK|0o666),("mnt_id",False),
                          ("uid",1),("gid",True),("nlink",0),("ctime_ns",-1)):
            a,b=deepcopy(before),sample_socket_edge(opened_boottime_ns=1015,closed_boottime_ns=1020)
            for record in (a,b): record["directories"]["provider"]["endpoint"]["object"][key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):
                s.verify_owned_socket_directories(a,b,worker_uid=1001,worker_gid=1002)

    def test_pure_replay_requires_two_distinct_windows_and_stable_manager_clock_and_resources(self):
        a=sample_socket_edge()
        for kwargs in ({"opened_boottime_ns":1010,"closed_boottime_ns":1020},
                       {"opened_boottime_ns":1011,"closed_boottime_ns":1011},
                       {"manager_pid":124},{"manager_start_ticks":46},{"boot_id":"bad"},
                       {"time_namespace_inode":902},{"worker_gid":1003}):
            b=sample_socket_edge(**({"opened_boottime_ns":1011,"closed_boottime_ns":1012}|kwargs))
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                s.verify_owned_socket_directories(a,b,worker_uid=1001,worker_gid=1002)
        for field,key in (("listener_handle","ino"),("object","ino")):
            b=sample_socket_edge(opened_boottime_ns=1020,closed_boottime_ns=1025)
            b["directories"]["request"][field][key]+=500
            with self.assertRaises(ValueError):
                s.verify_owned_socket_directories(a,b,worker_uid=1001,worker_gid=1002)

    def test_manager_context_requires_leader_and_caller_roots_and_time_namespace_match(self):
        base=sample_socket_edge()["manager"]
        for issue in ("none","other root","other time"):
            with self.subTest(issue=issue), ExitStack() as st:
                def mock(obj,fn,**kw): return st.enter_context(patch.object(obj,fn,**kw))
                mock(s.kernel,"_proc",return_value=(12,5));mock(s.os,"getpid",return_value=123)
                mock(s.threading,"get_native_id",return_value=124)
                mock(s.kernel,"_role",side_effect=lambda stack,p,n,m:(n,n));mock(s.kernel,"_proc_child",return_value=8)
                mock(s.kernel,"_frame",side_effect=lambda st,role,*args,kind:(base.copy(),
                    {"pid":role[0],"root":1 if kind=="manager" or issue!="other root" else 2},4,{}))
                mock(s.sensor,"_namespace",side_effect=[901,911 if issue=="other time" else 901])
                mock(s.sensor,"_boot_id",return_value="12345678-1234-4234-8234-123456789abc")
                if issue=="none":self.assertEqual(s._context(st,70)[0][0],base)
                else:
                    with self.assertRaises(ValueError):s._context(st,70)
