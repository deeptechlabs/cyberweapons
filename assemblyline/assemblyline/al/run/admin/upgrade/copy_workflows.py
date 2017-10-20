import uuid
from assemblyline.al.common import forge

ds = forge.get_datastore()
Classification = forge.get_classification()

for alert in ds.get_user("__workflow___favorites")['alert']:
    alert_id = str(uuid.uuid4())
    alert['hit_count'] = 0
    alert['id'] = alert_id
    alert['classification'] = Classification.UNRESTRICTED
    ds.save_workflow(alert_id, alert)
