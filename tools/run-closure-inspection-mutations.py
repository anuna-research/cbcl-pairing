import json,os,subprocess
from pathlib import Path
mutants=[
 ('inspection-uses-live-expiry','src/credential_v2/checkpoint.rs','expected_generation, CheckpointPurpose::Inspect)','expected_generation, CheckpointPurpose::ResumeAt(u64::MAX))',['--test','credential_v2_manual_session','closure_inspection']),
 ('ordinary-expiry-bypassed','src/credential_v2/checkpoint.rs','if let CheckpointPurpose::ResumeAt(now) = purpose {','if let CheckpointPurpose::ResumeAt(now) = CheckpointPurpose::Inspect {',['--test','credential_v2_manual_session','closure_inspection']),
 ('profile-binding','src/credential_v2/inspection.rs','if bootstrap.profile_digest() != &expected_profile_digest {','if false && bootstrap.profile_digest() != &expected_profile_digest {',['--test','credential_v2_manual_session','closure_inspection']),
 ('carrier-binding','src/credential_v2/bootstrap.rs','if &carrier != expected_carrier {','if false && &carrier != expected_carrier {',['--test','credential_v2_manual_session','closure_inspection']),
 ('expiry-shape','src/credential_v2/bootstrap.rs','if opened.expiry != Some(carrier.relay_expires_at()) {','if false && opened.expiry != Some(carrier.relay_expires_at()) {',['--lib','closure_inspection_rejects_authenticated_outer_expiry_shape_substitution']),
 ('terminal-receipt-binding','src/credential_v2/inspection.rs','.map(|last| (last.intent_digest, last.content_hash))','.map(|last| (last.intent_digest, [0; 32]))',['--test','credential_v2_allocator_session','receipt']),
]
out=Path('evidence/closure-inspection');records=[]
env={**os.environ,'CARGO_TARGET_DIR':os.environ.get('CARGO_TARGET_DIR','target'),'CARGO_PROFILE_DEV_DEBUG':'0','CARGO_PROFILE_TEST_DEBUG':'0','CARGO_INCREMENTAL':'0'}
for name,source,before,after,args in mutants:
 p=Path(source);original=p.read_text();assert original.count(before)==1,(name,original.count(before))
 try:
  p.write_text(original.replace(before,after))
  cmd=['cargo','test','--offline',*args]
  r=subprocess.run(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
  (out/(name+'.log')).write_text(r.stdout)
  killed=r.returncode!=0 and 'test result: FAILED.' in r.stdout
  records.append(dict(name=name,source=source,before=before,after=after,command=cmd,exitCode=r.returncode,behavioralRed=killed))
  (out/'mutations.json').write_text(json.dumps(records,indent=2)+'\n')
  print(name,'behavioral-red' if killed else 'NOT KILLED',flush=True)
  assert killed,name
 finally:p.write_text(original)
