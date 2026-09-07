from __future__ import annotations
from datetime import datetime, timezone
import json, re
_MISSING=object()

def parse_json(text):
    try:return json.loads(text)
    except Exception:return None

def get_path(data,path,default=_MISSING):
    cur=data
    if not path:return cur
    # Top-level JSON arrays are represented in event_context under _raw so
    # metadata (headers/query/meta) can coexist with the payload. Keep the
    # visual/mapping path syntax intuitive: [0].id still addresses the body.
    if str(path).startswith('[') and isinstance(data,dict) and isinstance(data.get('_raw'),list):
        cur=data['_raw']
    for part in re.findall(r'[^.\[\]]+|\[(\d+)\]', path):
        key=part if isinstance(part,str) else part
    tokens=[]
    for m in re.finditer(r'([^.\[\]]+)|\[(\d+)\]',path): tokens.append(int(m.group(2)) if m.group(2) is not None else m.group(1))
    try:
        for tok in tokens: cur=cur[tok] if isinstance(tok,int) else cur[tok]
        return cur
    except (KeyError,IndexError,TypeError): return default

def flatten_paths(data,prefix=''):
    out=[]
    if isinstance(data,dict):
        for k,v in data.items():
            p=f'{prefix}.{k}' if prefix else str(k); out.append((p,v,type_name(v))); out.extend(flatten_paths(v,p))
    elif isinstance(data,list):
        for i,v in enumerate(data):
            p=f'{prefix}[{i}]'; out.append((p,v,type_name(v))); out.extend(flatten_paths(v,p))
    return out

def type_name(v):
    if v is None:return 'null'
    if isinstance(v,bool):return 'boolean'
    if isinstance(v,int):return 'integer'
    if isinstance(v,float):return 'float'
    if isinstance(v,dict):return 'object'
    if isinstance(v,list):return 'array'
    return 'string'

def coerce_static(value,typ):
    if typ=='null':return None
    if typ=='boolean':return str(value).lower() in ('true','1','yes','on')
    if typ=='number':
        try:return int(value) if str(value).isdigit() else float(value)
        except:return 0
    if typ in ('object','array'):
        try:
            parsed=json.loads(value)
        except Exception as e:raise ValueError(f'Ungültiger JSON-Wert für {typ}') from e
        if typ=='object' and not isinstance(parsed,dict):raise ValueError('Statischer Wert muss ein Object sein')
        if typ=='array' and not isinstance(parsed,list):raise ValueError('Statischer Wert muss ein Array sein')
        return parsed
    return str(value)

def apply_transform(value, tr):
    op=tr.get('op'); arg=tr.get('arg','')
    if op=='lowercase': return str(value).lower()
    if op=='uppercase': return str(value).upper()
    if op=='trim': return str(value).strip()
    if op=='prefix': return str(arg)+str(value)
    if op=='suffix': return str(value)+str(arg)
    if op=='replace':
        a,b=(str(arg).split('=>',1)+[''])[:2]; return str(value).replace(a,b)
    if op=='substring':
        p=str(arg).split(':'); return str(value)[int(p[0] or 0): int(p[1]) if len(p)>1 and p[1] else None]
    if op in ('add','subtract','multiply','divide'):
        n=float(value); a=float(arg)
        return {'add':n+a,'subtract':n-a,'multiply':n*a,'divide':n/a}[op]
    if op=='round': return round(float(value),int(arg or 0))
    if op=='invert': return not bool(value)
    if op=='bool_map':
        falsev,truev=(str(arg).split('|',1)+[''])[:2]; return truev if bool(value) else falsev
    if op=='unix_to_iso': return datetime.fromtimestamp(float(value),tz=timezone.utc).isoformat()
    if op=='iso_to_unix': return int(datetime.fromisoformat(str(value).replace('Z','+00:00')).timestamp())
    if op=='date_format': return datetime.fromisoformat(str(value).replace('Z','+00:00')).strftime(str(arg))
    return value

def set_path(root,path,value):
    tokens=[]
    for m in re.finditer(r'([^.\[\]]+)|\[(\d+)\]',path): tokens.append(int(m.group(2)) if m.group(2) is not None else m.group(1))
    cur=root
    for i,tok in enumerate(tokens):
        last=i==len(tokens)-1
        nxt=tokens[i+1] if not last else None
        if isinstance(tok,int):
            if not isinstance(cur,list): raise ValueError('array path requires array parent')
            while len(cur)<=tok: cur.append({} if not isinstance(nxt,int) else [])
            if last: cur[tok]=value
            else: cur=cur[tok]
        else:
            if last: cur[tok]=value
            else:
                if tok not in cur: cur[tok]=[] if isinstance(nxt,int) else {}
                cur=cur[tok]

def build_mapping(data,mappings):
    out={}
    for m in mappings:
        if m.source_type=='field':
            val=get_path(data,m.source_value,_MISSING)
            if val is _MISSING:
                if m.fallback_json is not None: val=m.fallback_json
                else: raise ValueError(f'Feld im Request nicht vorhanden: {m.source_value}')
        elif m.source_type=='static': val=coerce_static(m.source_value,m.static_type)
        elif m.source_type=='combine':
            val=re.sub(r'\{\{\s*([^}]+?)\s*\}\}',lambda x:str(get_path(data,x.group(1),'')),m.source_value)
        else: val=m.source_value
        for tr in (m.transforms or []): val=apply_transform(val,tr)
        set_path(out,m.target_path,val)
    return out

def eval_rule(data,rule):
    v=get_path(data,rule.field_path,_MISSING); op=rule.operator; target=rule.value_json
    if op=='exists':return v is not _MISSING
    if op=='not_exists':return v is _MISSING
    if op=='empty':return v is _MISSING or v in ('',None,[],{})
    if op=='not_empty':return v is not _MISSING and v not in ('',None,[],{})
    if op=='true':return v is True
    if op=='false':return v is False
    if v is _MISSING:return False
    if op=='equals':return v==target or str(v)==str(target)
    if op=='not_equals':return not (v==target or str(v)==str(target))
    if op=='contains':return str(target) in str(v)
    if op=='not_contains':return str(target) not in str(v)
    if op=='starts_with':return str(v).startswith(str(target))
    if op=='ends_with':return str(v).endswith(str(target))
    if op in ('gt','lt','gte','lte'):
        try:a,b=float(v),float(target)
        except:return False
        return {'gt':a>b,'lt':a<b,'gte':a>=b,'lte':a<=b}[op]
    return False

def eval_flow(data,flow):
    if not flow.rules:return True
    vals=[eval_rule(data,r) for r in flow.rules]
    return all(vals) if flow.condition_logic=='AND' else any(vals)
