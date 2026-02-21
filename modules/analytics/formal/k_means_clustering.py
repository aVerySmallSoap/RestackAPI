import pprint

import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

from sqlalchemy.orm import Session
from sqlalchemy import func

from modules.db.database import Database
from modules.db.table_collection import Report, Scan

def vulnerability_pattern_clustering(n_clusters: int = 3):
    """
    Cluster targets by vulnerability patterns
    """
    db = Database()
    engine = db.engine

    with Session(engine) as session:
        # Get features per target
        target_features = session.query(
            Scan.target_url,
            func.avg(Report.total_vulnerabilities).label('avg_vulns'),
            func.avg(Report.critical_count).label('avg_critical'),
            func.count(Report.id).label('scan_count')
        ).join(Report, Scan.report_id == Report.id
               ).group_by(Scan.target_url).all()

        df = pd.DataFrame(target_features, columns=[
            'target_url', 'avg_vulns', 'avg_critical', 'scan_count'
        ])

        # Prepare features
        X = df[['avg_vulns', 'avg_critical', 'scan_count']]
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # K-means clustering
        kmeans = KMeans(n_clusters=n_clusters, random_state=42)
        df['cluster'] = kmeans.fit_predict(X_scaled)

        # Analyze clusters
        clusters = {}
        for i in range(n_clusters):
            cluster_data = df[df['cluster'] == i]
            clusters[f"cluster_{i}"] = {
                "targets": cluster_data['target_url'].tolist(),
                "characteristics": {
                    "avg_vulnerabilities": float(cluster_data['avg_vulns'].mean()),
                    "avg_critical": float(cluster_data['avg_critical'].mean()),
                    "avg_scan_count": float(cluster_data['scan_count'].mean())
                },
                "risk_profile": classify_cluster_risk(cluster_data)
            }

        return {
            "n_clusters": n_clusters,
            "clusters": clusters
            # "silhouette_score": float(silhouette_score(X_scaled, kmeans.labels_))
        }


def classify_cluster_risk(cluster_df):
    """Classify cluster as high/medium/low risk"""
    avg_vulns = cluster_df['avg_vulns'].mean()
    if avg_vulns > 50:
        return "high_risk"
    elif avg_vulns > 20:
        return "medium_risk"
    else:
        return "low_risk"



pprint.pprint(vulnerability_pattern_clustering())