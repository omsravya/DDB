from datetime import datetime
from functools import wraps

from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

from flask import (
    Flask,
    flash,
    has_request_context,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
import psycopg2
import os
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME=os.environ.get("EMAIL_USER"),
    MAIL_PASSWORD=os.environ.get("EMAIL_PASS")
)

mail = Mail(app)

serializer = URLSafeTimedSerializer(app.secret_key)

def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset')

def verify_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=expiration)
        return email
    except:
        return None

raw_database_url = os.environ.get("DATABASE_URL")
DATABASE_URL = (
    raw_database_url.replace("postgres://", "postgresql://", 1)
    if raw_database_url
    else None
)

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set. Please configure environment variable.")

# app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
app.secret_key = os.environ.get("FLASK_SECRET_KEY")

ROLE_RANK = {
    "researcher": 1,
    "reviewer": 2,
    "coder": 3,
    "admin": 4,
}

ROLE_LABELS = {
    "researcher": "User",
    "reviewer": "Reviewer",
    "coder": "Researcher",
    "admin": "Admin",
}

def query_db(query, params=None):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(query, params or ())
    data = cur.fetchall()
    colnames = [desc[0] for desc in cur.description]
    cur.close()
    conn.close()
    return colnames, data


def execute_db(query, params=None):
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(query, params or ())
    conn.commit()
    cur.close()
    conn.close()


def query_one(query, params=None):
    columns, rows = query_db(query, params)
    if not rows:
        return None
    return dict(zip(columns, rows[0]))


def query_scalar(query, params=None):
    result = query_one(query, params)
    if not result:
        return None
    return next(iter(result.values()))


def ensure_users_password_column():
    try:
        execute_db("ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT")
    except psycopg2.Error:
        return False
    return True


def ensure_signup_request_table():
    try:
        execute_db(
            """
            CREATE TABLE IF NOT EXISTS signup_request (
                signup_request_id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                requested_role TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                review_comments TEXT,
                requested_at TIMESTAMP NOT NULL DEFAULT NOW(),
                reviewed_at TIMESTAMP,
                reviewed_by TEXT
            )
            """
        )
    except psycopg2.Error:
        return False
    return True


def ensure_password_reset_request_table():
    try:
        execute_db(
            """
            CREATE TABLE IF NOT EXISTS password_reset_request (
                password_reset_request_id SERIAL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                name TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_at TIMESTAMP NOT NULL DEFAULT NOW(),
                reviewed_at TIMESTAMP,
                reviewed_by TEXT
            )
            """
        )
    except psycopg2.Error:
        return False
    return True


def ensure_fact_type_table():
    try:
        execute_db(
            """
            CREATE TABLE IF NOT EXISTS fact_type (
                fact_type_id SERIAL PRIMARY KEY,
                fact_type_name TEXT NOT NULL,
                fact_type_description TEXT
            )
            """
        )
    except psycopg2.Error:
        return False
    return True


def ensure_company_cusip_column():
    try:
        execute_db("ALTER TABLE company ADD COLUMN IF NOT EXISTS cusip TEXT")
    except psycopg2.Error:
        return False
    return True


def rows_to_dicts(columns, rows):
    return [dict(zip(columns, row)) for row in rows]


def first_present(record, preferred_keys):
    for key in preferred_keys:
        value = record.get(key)
        if value not in (None, ""):
            return value
    return None


def parse_datetime_value(value):
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        return value

    value_as_text = str(value).strip()
    if not value_as_text:
        return None

    candidates = [
        value_as_text,
        value_as_text.replace("Z", "+00:00"),
        value_as_text.split(".")[0],
    ]

    for candidate in candidates:
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def choose_display_fields(columns, preferred_fields, limit=3):
    selected = [field for field in preferred_fields if field in columns]
    if len(selected) >= limit:
        return selected[:limit]

    for column in columns:
        if column not in selected:
            selected.append(column)
        if len(selected) == limit:
            break

    return selected


def build_table_records(columns, rows, preferred_fields, limit=5):
    fields = choose_display_fields(columns, preferred_fields)
    records = []

    for row in rows[:limit]:
        record = dict(zip(columns, row))
        records.append({field: record.get(field) for field in fields})

    return fields, records


def build_table_records_from_dicts(records, preferred_fields, limit=5):
    if not records:
        return preferred_fields[: min(len(preferred_fields), 3)], []

    available_columns = list(records[0].keys())
    fields = choose_display_fields(available_columns, preferred_fields)
    preview_rows = []

    for record in records[:limit]:
        preview_rows.append({field: record.get(field) for field in fields})

    return fields, preview_rows


def sort_recent_records(records, date_fields):
    def sort_key(record):
        for field in date_fields:
            parsed = parse_datetime_value(record.get(field))
            if parsed is not None:
                return parsed
        return datetime.min

    return sorted(records, key=sort_key, reverse=True)


def build_recent_activity(announcements, reviews, audit_logs, limit=8):
    activity = []

    for announcement in announcements:
        activity.append(
            {
                "kind": "Announcement",
                "title": first_present(
                    announcement,
                    ["content", "url", "incident_id", "announcement_id"],
                ),
                "meta": "Incident {}".format(
                    first_present(announcement, ["incident_id"]) or "Unknown"
                ),
                "timestamp": first_present(
                    announcement,
                    ["announcement_date", "created_at", "updated_at"],
                ),
            }
        )

    for review in reviews:
        activity.append(
            {
                "kind": "Fact review",
                "title": first_present(
                    review,
                    ["status", "review_notes", "fact_id", "review_id"],
                ),
                "meta": "Fact {}".format(first_present(review, ["fact_id"]) or "Unknown"),
                "timestamp": first_present(
                    review,
                    ["reviewed_at", "created_at", "updated_at"],
                ),
            }
        )

    for log in audit_logs:
        actor = first_present(log, ["user_id", "actor_id", "user_name"])
        action = first_present(log, ["action", "event_type", "description", "table_name"])
        activity.append(
            {
                "kind": "Audit log",
                "title": action or "Audit event",
                "meta": "Actor {}".format(actor) if actor else "System event",
                "timestamp": first_present(
                    log,
                    ["created_at", "event_time", "timestamp", "logged_at"],
                ),
            }
        )

    activity.sort(
        key=lambda item: parse_datetime_value(item["timestamp"]) or datetime.min,
        reverse=True,
    )
    return activity[:limit]


def slugify_label(value):
    return value.lower().replace(" ", "-").replace("_", "-")


def build_data_view_table(title, columns, rows, description):
    return {
        "id": slugify_label(title),
        "title": title,
        "description": description,
        "columns": columns,
        "rows": rows_to_dicts(columns, rows),
        "row_count": len(rows),
        "column_count": len(columns),
    }


def strip_sensitive_columns(columns, rows, hidden_columns):
    visible_indexes = [
        index for index, column in enumerate(columns) if column not in hidden_columns
    ]
    visible_columns = [columns[index] for index in visible_indexes]
    visible_rows = [
        tuple(row[index] for index in visible_indexes)
        for row in rows
    ]
    return visible_columns, visible_rows


def reorder_columns(columns, preferred_order):
    ordered = [column for column in preferred_order if column in columns]
    ordered.extend(column for column in columns if column not in ordered)
    return ordered


def reorder_rows(columns, rows, preferred_order):
    ordered_columns = reorder_columns(columns, preferred_order)
    column_indexes = {column: index for index, column in enumerate(columns)}
    ordered_rows = [
        tuple(row[column_indexes[column]] for column in ordered_columns)
        for row in rows
    ]
    return ordered_columns, ordered_rows


def normalize_confidence_value(value):
    if value in (None, ""):
        return value

    normalized = str(value).strip().lower()
    mapping = {
        "sample fact note 1": "high",
        "sample fact note 2": "medium",
        "sample fact note 3": "low",
    }
    return mapping.get(normalized, normalized)


def choose_fact_type_name_column(columns):
    return first_present(
        {column: column for column in columns},
        ["fact_type_name", "name", "title", "label", "category"],
    )


def choose_fact_type_description_column(columns):
    return first_present(
        {column: column for column in columns},
        ["fact_type_description", "description", "details", "summary"],
    )


def enrich_fact_rows_with_type_details(
    fact_columns,
    fact_rows,
    fact_type_columns,
    fact_type_rows,
    user_columns=None,
    user_rows=None,
):
    fact_records = rows_to_dicts(fact_columns, fact_rows)
    fact_type_records = rows_to_dicts(fact_type_columns, fact_type_rows)
    user_records = rows_to_dicts(user_columns, user_rows) if user_columns and user_rows else []

    fact_type_id_column = choose_fact_identifier_column(fact_type_columns)
    fact_type_name_column = choose_fact_type_name_column(fact_type_columns)
    fact_type_description_column = choose_fact_type_description_column(fact_type_columns)
    fact_type_column = choose_fact_type_column(fact_columns)
    user_id_column = get_user_identifier_column(user_columns or [])

    fact_types_by_id = {
        str(record.get(fact_type_id_column)): record
        for record in fact_type_records
        if fact_type_id_column and record.get(fact_type_id_column) is not None
    }
    users_by_id = {
        str(record.get(user_id_column)): record
        for record in user_records
        if user_id_column and record.get(user_id_column) is not None
    }

    enriched_columns = list(fact_columns)
    if "fact_type_name" not in enriched_columns:
        enriched_columns.append("fact_type_name")
    if "fact_type_description" not in enriched_columns:
        enriched_columns.append("fact_type_description")

    enriched_rows = []
    for fact in fact_records:
        fact_type = fact_types_by_id.get(str(fact.get(fact_type_column)))
        enriched_record = dict(fact)
        for confidence_column in ["confidence_level", "confidence"]:
            if confidence_column in enriched_record:
                enriched_record[confidence_column] = normalize_confidence_value(
                    enriched_record.get(confidence_column)
                )
        for user_ref_column in ["coded_by", "entered_by", "created_by"]:
            if user_ref_column in enriched_record and enriched_record.get(user_ref_column) is not None:
                user_record = users_by_id.get(str(enriched_record.get(user_ref_column)))
                enriched_record[user_ref_column] = first_present(
                    user_record or {},
                    ["name", "full_name", "email", user_id_column],
                )
        enriched_record["fact_type_name"] = (
            fact_type.get(fact_type_name_column)
            if fact_type and fact_type_name_column
            else None
        )
        enriched_record["fact_type_description"] = (
            fact_type.get(fact_type_description_column)
            if fact_type and fact_type_description_column
            else None
        )
        enriched_rows.append(tuple(enriched_record.get(column) for column in enriched_columns))

    return enriched_columns, enriched_rows


def hide_fact_type_id_from_fact_view(columns, rows):
    hidden_columns = {"fact_type_id", "fact_type", "type", "category"}
    return strip_sensitive_columns(columns, rows, hidden_columns)


def get_user_identifier_column(columns):
    if "user_id" in columns:
        return "user_id"
    if "id" in columns:
        return "id"
    return None


def get_record_identifier(record, preferred_keys):
    return first_present(record, preferred_keys)


def get_table_metadata(table_name):
    columns, rows = query_db(
        """
        SELECT
            c.column_name,
            c.data_type,
            c.is_nullable,
            c.column_default,
            CASE WHEN tc.constraint_type = 'PRIMARY KEY' THEN TRUE ELSE FALSE END AS is_primary_key,
            ccu.table_name AS foreign_table_name,
            ccu.column_name AS foreign_column_name
        FROM information_schema.columns c
        LEFT JOIN information_schema.key_column_usage kcu
            ON c.table_schema = kcu.table_schema
            AND c.table_name = kcu.table_name
            AND c.column_name = kcu.column_name
        LEFT JOIN information_schema.table_constraints tc
            ON kcu.constraint_name = tc.constraint_name
            AND kcu.table_schema = tc.table_schema
            AND kcu.table_name = tc.table_name
        LEFT JOIN information_schema.constraint_column_usage ccu
            ON ccu.constraint_name = tc.constraint_name
            AND ccu.table_schema = tc.table_schema
        WHERE c.table_schema = 'public'
          AND c.table_name = %s
        ORDER BY c.ordinal_position
        """,
        (table_name,),
    )
    return rows_to_dicts(columns, rows)


def should_skip_insert_column(column, table_name):
    if column["is_primary_key"]:
        return True
    if column["column_default"] and "nextval" in str(column["column_default"]):
        return True
    if column["column_name"] == f"{table_name}_id" and column["column_default"]:
        return True
    return False


def pick_option_label(record, fallback_column):
    label = first_present(
        record,
        [
            "incident_description",
            "description",
            "summary",
            "name",
            "title",
            "company_name",
            "source_name",
            "email",
            "content",
            "url",
            fallback_column,
        ],
    )
    return str(label) if label is not None else "Unknown"


def summarize_fact(record):
    label = first_present(
        record,
        [
            "statement",
            "content",
            "description",
            "value",
            "fact_value",
            "fact_text",
            "summary",
            "fact_id",
            "id",
        ],
    )
    meta = []
    fact_type = first_present(record, ["fact_type_name", "fact_type_id", "type", "category"])
    incident = first_present(record, ["incident_id", "incident"])
    source = first_present(record, ["source_id", "source"])

    if fact_type is not None:
        meta.append(f"Type {fact_type}")
    if incident is not None:
        meta.append(f"Incident {incident}")
    if source is not None:
        meta.append(f"Source {source}")

    return {
        "id": get_record_identifier(record, ["fact_id", "id"]),
        "title": str(label) if label is not None else "Untitled fact",
        "meta": " • ".join(meta) if meta else "Fact record",
        "status": first_present(
            record,
            ["review_status", "status", "approval_status", "fact_status"],
        ),
    }


def choose_review_status_column(columns):
    for column in ["decision", "status", "review_status", "outcome"]:
        if column in columns:
            return column
    return None


def choose_review_comment_column(columns):
    for column in ["comments", "comment", "review_notes", "notes", "feedback"]:
        if column in columns:
            return column
    return None


def choose_review_fact_column(columns):
    for column in ["fact_id", "fact"]:
        if column in columns:
            return column
    return None


def choose_reviewer_user_column(columns):
    for column in ["reviewer_id", "user_id", "reviewed_by"]:
        if column in columns:
            return column
    return None


def choose_review_timestamp_column(columns):
    for column in ["reviewed_at", "created_at", "updated_at", "timestamp"]:
        if column in columns:
            return column
    return None


def choose_fact_identifier_column(columns):
    for column in ["fact_id", "id"]:
        if column in columns:
            return column
    return None


def choose_fact_status_column(columns):
    for column in ["review_status", "approval_status", "fact_status", "status"]:
        if column in columns:
            return column
    return None


def map_decision_to_fact_status(decision):
    return {
        "Approved": "approved",
        "Rejected": "rejected",
    }.get(decision, decision.lower())


def update_fact_status(fact_id, decision):
    fact_metadata = get_table_metadata("fact")
    fact_columns = [column["column_name"] for column in fact_metadata]
    identifier_column = choose_fact_identifier_column(fact_columns)
    status_column = choose_fact_status_column(fact_columns)

    if not identifier_column or not status_column:
        return False

    execute_db(
        f"UPDATE fact SET {status_column} = %s WHERE {identifier_column} = %s",
        (map_decision_to_fact_status(decision), fact_id),
    )
    return True


def build_review_insert_payload(review_columns, fact_id, decision, comments, reviewer_id):
    payload = {}

    fact_column = choose_review_fact_column(review_columns)
    if fact_column:
        payload[fact_column] = fact_id

    status_column = choose_review_status_column(review_columns)
    if status_column:
        payload[status_column] = decision

    comment_column = choose_review_comment_column(review_columns)
    if comment_column:
        payload[comment_column] = comments

    reviewer_column = choose_reviewer_user_column(review_columns)
    if reviewer_column and reviewer_id is not None:
        payload[reviewer_column] = reviewer_id

    timestamp_column = choose_review_timestamp_column(review_columns)
    if timestamp_column and timestamp_column not in payload:
        payload[timestamp_column] = datetime.utcnow()

    return payload


def insert_record_from_payload(table_name, payload):
    if not payload:
        raise ValueError("No valid review fields were found in the destination table.")

    column_names = list(payload.keys())
    placeholders = ", ".join(["%s"] * len(column_names))
    columns_sql = ", ".join(column_names)
    values = [payload[column] for column in column_names]

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(
        f"INSERT INTO {table_name} ({columns_sql}) VALUES ({placeholders})",
        values,
    )
    conn.commit()
    cur.close()
    conn.close()


def build_latest_reviews_by_fact():
    review_cols, review_rows = query_db("SELECT * FROM fact_review")
    review_records = rows_to_dicts(review_cols, review_rows)
    fact_column = choose_review_fact_column(review_cols)
    status_column = choose_review_status_column(review_cols)
    comment_column = choose_review_comment_column(review_cols)
    timestamp_column = choose_review_timestamp_column(review_cols)

    if not fact_column:
        return {}

    review_records.sort(
        key=lambda record: parse_datetime_value(record.get(timestamp_column)) or datetime.min,
        reverse=True,
    )

    latest = {}
    for review in review_records:
        fact_id = review.get(fact_column)
        if fact_id in latest:
            continue
        latest[fact_id] = {
            "decision": review.get(status_column) if status_column else None,
            "comments": review.get(comment_column) if comment_column else None,
            "timestamp": review.get(timestamp_column) if timestamp_column else None,
        }

    return latest


def get_foreign_key_options(foreign_table, foreign_column):
    columns, rows = query_db(f"SELECT * FROM {foreign_table} ORDER BY 1 LIMIT 200")
    records = rows_to_dicts(columns, rows)
    options = []
    for record in records:
        value = record.get(foreign_column)
        options.append(
            {
                "value": value,
                "label": pick_option_label(record, foreign_column),
            }
        )
    return options


def infer_field_type(column):
    data_type = (column["data_type"] or "").lower()
    column_name = column["column_name"]
    if column["foreign_table_name"]:
        return "select"
    if column_name in {"confidence_level", "confidence"}:
        return "select-enum"
    if "date" in data_type and "timestamp" not in data_type:
        return "date"
    if "timestamp" in data_type:
        return "datetime-local"
    if data_type in {"integer", "bigint", "smallint", "numeric", "real", "double precision"}:
        return "number"
    if data_type == "boolean":
        return "select-boolean"
    if data_type == "text" or column_name in {"content", "description", "notes", "summary"}:
        return "textarea"
    return "text"


def field_options_for_column(column_name):
    if column_name in {"confidence_level", "confidence"}:
        return [
            {"value": "high", "label": "High"},
            {"value": "medium", "label": "Medium"},
            {"value": "low", "label": "Low"},
        ]
    return []


def field_label_for_column(column):
    column_name = column["column_name"]
    if column["foreign_table_name"] == "company" and column_name in {"company_id", "company"}:
        return "Company Name"
    if column["foreign_table_name"] == "incident" and column_name in {"incident_id", "incident"}:
        return "Incident"
    if column["foreign_table_name"] == "announcement" and column_name in {"announcement_id", "announcement"}:
        return "Announcements"
    if column["foreign_table_name"] == "fact_type" and column_name in {"fact_type_id", "fact_type"}:
        return "Fact Type"
    if column["foreign_table_name"] == "source" and column_name in {"source_id", "source"}:
        return "Source"
    return column_name.replace("_", " ").title()


def build_dynamic_form(table_name, title, description):
    fields = []
    for column in get_table_metadata(table_name):
        if should_skip_insert_column(column, table_name):
            continue

        field = {
            "name": column["column_name"],
            "label": field_label_for_column(column),
            "required": column["is_nullable"] == "NO" and not column["column_default"],
            "input_type": infer_field_type(column),
            "options": field_options_for_column(column["column_name"]),
        }

        if column["foreign_table_name"]:
            field["options"] = get_foreign_key_options(
                column["foreign_table_name"],
                column["foreign_column_name"],
            )

        fields.append(field)

    return {
        "table_name": table_name,
        "title": title,
        "description": description,
        "fields": fields,
    }


def normalize_submitted_value(field, raw_value):
    value = raw_value.strip()
    if value == "":
        return None

    if field["input_type"] == "select-boolean":
        return value.lower() == "true"

    return value


def insert_dynamic_record(table_name, fields, form_data):
    column_names = []
    values = []

    for field in fields:
        value = normalize_submitted_value(field, form_data.get(field["name"], ""))
        if value is None and field["required"]:
            raise ValueError(f"{field['label']} is required.")
        if value is not None:
            column_names.append(field["name"])
            values.append(value)

    if not column_names:
        raise ValueError("At least one field is required.")

    placeholders = ", ".join(["%s"] * len(column_names))
    columns_sql = ", ".join(column_names)

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(
        f"INSERT INTO {table_name} ({columns_sql}) VALUES ({placeholders})",
        values,
    )
    conn.commit()
    cur.close()
    conn.close()


def update_dynamic_record(table_name, fields, form_data, identifier_column, identifier_value):
    assignments = []
    values = []

    for field in fields:
        value = normalize_submitted_value(field, form_data.get(field["name"], ""))
        if value is None and field["required"]:
            raise ValueError(f"{field['label']} is required.")
        assignments.append(f"{field['name']} = %s")
        values.append(value)

    if not assignments:
        raise ValueError("No editable fields were found.")

    values.append(identifier_value)
    execute_db(
        f"UPDATE {table_name} SET {', '.join(assignments)} WHERE {identifier_column} = %s",
        values,
    )


def sample_value_for_column(column, sample_index):
    column_name = column["column_name"]
    data_type = (column["data_type"] or "").lower()

    named_values = {
        "statement": [
            "Data Exfiltrated = Yes",
            "Ransom Note Published = Yes",
            "Systems Encrypted = Yes",
        ],
        "content": [
            "Data Exfiltrated = Yes",
            "Ransom Note Published = Yes",
            "Systems Encrypted = Yes",
        ],
        "description": [
            "External reporting indicates data exfiltration occurred.",
            "Public leak-site evidence suggests a ransom note was posted.",
            "Available disclosures indicate encryption impacted internal systems.",
        ],
        "summary": [
            "Evidence points to exfiltration.",
            "Evidence points to public extortion messaging.",
            "Evidence points to encryption impact.",
        ],
        "value": ["Yes", "Yes", "Yes"],
        "fact_value": ["Yes", "Yes", "Yes"],
        "fact_text": [
            "Data Exfiltrated = Yes",
            "Ransom Note Published = Yes",
            "Systems Encrypted = Yes",
        ],
        "status": ["pending_review", "pending_review", "pending_review"],
        "confidence_level": ["high", "medium", "low"],
        "confidence": ["high", "medium", "low"],
    }

    if column_name in named_values:
        values = named_values[column_name]
        return values[sample_index % len(values)]

    if "date" in data_type and "timestamp" not in data_type:
        return datetime.utcnow().date()
    if "timestamp" in data_type:
        return datetime.utcnow()
    if data_type == "boolean":
        return True
    if data_type in {"integer", "bigint", "smallint"}:
        return sample_index + 1
    if data_type in {"numeric", "real", "double precision"}:
        return float(sample_index + 1)
    if data_type == "text":
        return f"Sample fact note {sample_index + 1}"
    return f"Sample {column_name.replace('_', ' ')} {sample_index + 1}"


def build_sample_fact_payloads(sample_count=3):
    fact_metadata = get_table_metadata("fact")
    payloads = []

    reference_cache = {}

    for sample_index in range(sample_count):
        payload = {}
        for column in fact_metadata:
            if should_skip_insert_column(column, "fact"):
                continue

            column_name = column["column_name"]
            is_required = column["is_nullable"] == "NO" and not column["column_default"]

            if column["foreign_table_name"]:
                cache_key = (column["foreign_table_name"], column["foreign_column_name"])
                if cache_key not in reference_cache:
                    options = get_foreign_key_options(*cache_key)
                    reference_cache[cache_key] = options
                options = reference_cache[cache_key]
                if options:
                    payload[column_name] = options[sample_index % len(options)]["value"]
                elif is_required:
                    raise ValueError(
                        f"Cannot seed facts because required reference data is missing for {column_name}."
                    )
                continue

            payload[column_name] = sample_value_for_column(column, sample_index)

        payloads.append(payload)

    return payloads


def normalize_text(value):
    if value is None:
        return ""
    return str(value).strip().lower()


def choose_company_name_column(columns):
    for column in ["company_name", "name", "title"]:
        if column in columns:
            return column
    return None


def choose_company_id_column(columns):
    for column in ["company_id", "id"]:
        if column in columns:
            return column
    return None


def choose_incident_company_column(columns):
    for column in ["company_id", "company"]:
        if column in columns:
            return column
    return None


def choose_incident_date_column(columns):
    for column in ["incident_date", "discovered_at", "created_at", "updated_at"]:
        if column in columns:
            return column
    return None


def choose_incident_id_column(columns):
    for column in ["incident_id", "id"]:
        if column in columns:
            return column
    return None


def choose_fact_incident_column(columns):
    for column in ["incident_id", "incident"]:
        if column in columns:
            return column
    return None


def choose_fact_type_column(columns):
    for column in ["fact_type_id", "fact_type", "type", "category"]:
        if column in columns:
            return column
    return None


def choose_fact_summary_column(columns):
    for column in ["statement", "content", "description", "value", "fact_value", "fact_text", "summary"]:
        if column in columns:
            return column
    return None


def choose_announcement_incident_column(columns):
    for column in ["incident_id", "incident"]:
        if column in columns:
            return column
    return None


def choose_source_id_column(columns):
    for column in ["source_id", "id"]:
        if column in columns:
            return column
    return None


def choose_source_name_column(columns):
    for column in ["source_name", "name", "title"]:
        if column in columns:
            return column
    return None


def build_incident_detail(incident_id):
    companies_cols, companies = query_db("SELECT * FROM company")
    incidents_cols, incidents = query_db("SELECT * FROM incident")
    announcements_cols, announcements = query_db("SELECT * FROM announcement")
    facts_cols, facts = query_db("SELECT * FROM fact")
    fact_type_cols, fact_types = query_db("SELECT * FROM fact_type")
    sources_cols, sources = query_db("SELECT * FROM source")

    company_records = rows_to_dicts(companies_cols, companies)
    incident_records = rows_to_dicts(incidents_cols, incidents)
    announcement_records = rows_to_dicts(announcements_cols, announcements)
    fact_records = rows_to_dicts(facts_cols, facts)
    fact_type_records = rows_to_dicts(fact_type_cols, fact_types)
    source_records = rows_to_dicts(sources_cols, sources)

    incident_id_column = choose_incident_id_column(incidents_cols)
    incident = next(
        (record for record in incident_records if str(record.get(incident_id_column)) == str(incident_id)),
        None,
    )
    if not incident:
        return None

    company_id_column = choose_company_id_column(companies_cols)
    company_name_column = choose_company_name_column(companies_cols)
    incident_company_column = choose_incident_company_column(incidents_cols)
    incident_date_column = choose_incident_date_column(incidents_cols)
    company = next(
        (
            record
            for record in company_records
            if str(record.get(company_id_column)) == str(incident.get(incident_company_column))
        ),
        None,
    ) if company_id_column and incident_company_column else None

    source_id_column = choose_source_id_column(sources_cols)
    source_name_column = choose_source_name_column(sources_cols)
    source_by_id = {
        str(record.get(source_id_column)): record
        for record in source_records
        if source_id_column and record.get(source_id_column) is not None
    }

    announcement_incident_column = choose_announcement_incident_column(announcements_cols)
    incident_announcements = []
    for announcement in announcement_records:
        if str(announcement.get(announcement_incident_column)) != str(incident_id):
            continue
        source = source_by_id.get(str(first_present(announcement, ["source_id", "source"])))
        incident_announcements.append(
            {
                "title": first_present(announcement, ["url", "content", "announcement_id"]),
                "url": announcement.get("url"),
                "source_name": source.get(source_name_column) if source and source_name_column else None,
                "date": first_present(announcement, ["announcement_date", "created_at"]),
            }
        )

    fact_type_id_column = choose_fact_identifier_column(fact_type_cols)
    fact_type_name_column = first_present(
        {column: column for column in fact_type_cols},
        ["fact_type_name", "name", "title", "label", "category"],
    )
    fact_type_by_id = {
        str(record.get(fact_type_id_column)): record
        for record in fact_type_records
        if fact_type_id_column and record.get(fact_type_id_column) is not None
    }
    fact_incident_column = choose_fact_incident_column(facts_cols)
    fact_type_column = choose_fact_type_column(facts_cols)
    fact_summary_column = choose_fact_summary_column(facts_cols)
    incident_facts = []
    for fact in fact_records:
        if str(fact.get(fact_incident_column)) != str(incident_id):
            continue
        fact_type = fact_type_by_id.get(str(fact.get(fact_type_column)))
        incident_facts.append(
            {
                "label": (
                    fact_type.get(fact_type_name_column)
                    if fact_type and fact_type_name_column
                    else first_present(fact, ["fact_type", "type", "category", "fact_type_id"])
                ),
                "value": fact.get(fact_summary_column) if fact_summary_column else summarize_fact(fact)["title"],
                "status": first_present(fact, ["review_status", "approval_status", "fact_status", "status"]),
            }
        )

    return {
        "incident_id": incident.get(incident_id_column),
        "company_name": company.get(company_name_column) if company and company_name_column else "Unknown company",
        "incident_date": incident.get(incident_date_column) if incident_date_column else None,
        "incident_status": first_present(incident, ["status", "incident_status"]),
        "industry": first_present(company or {}, ["industry", "sector"]),
        "country": first_present(company or {}, ["country", "country_name", "region"]),
        "announcements": incident_announcements,
        "facts": incident_facts,
    }


def build_research_records(companies, incidents, facts, fact_types):
    company_name_column = choose_company_name_column(companies["columns"])
    company_id_column = choose_company_id_column(companies["columns"])
    incident_company_column = choose_incident_company_column(incidents["columns"])
    incident_date_column = choose_incident_date_column(incidents["columns"])
    incident_id_column = choose_incident_id_column(incidents["columns"])
    fact_incident_column = choose_fact_incident_column(facts["columns"])
    fact_type_column = choose_fact_type_column(facts["columns"])
    fact_summary_column = choose_fact_summary_column(facts["columns"])
    fact_id_column = choose_fact_identifier_column(facts["columns"])

    fact_type_id_column = choose_fact_identifier_column(fact_types["columns"])
    fact_type_name_column = first_present(
        {column: column for column in fact_types["columns"]},
        ["fact_type_name", "name", "title", "label", "category"],
    )

    companies_by_id = {}
    for company in companies["records"]:
        company_id = company.get(company_id_column) if company_id_column else None
        companies_by_id[company_id] = company

    fact_type_by_id = {}
    for fact_type in fact_types["records"]:
        type_id = fact_type.get(fact_type_id_column) if fact_type_id_column else None
        fact_type_by_id[type_id] = fact_type

    incidents_by_id = {}
    for incident in incidents["records"]:
        incident_id = incident.get(incident_id_column) if incident_id_column else None
        incidents_by_id[incident_id] = incident

    records = []
    for fact in facts["records"]:
        incident = incidents_by_id.get(fact.get(fact_incident_column))
        company = companies_by_id.get(incident.get(incident_company_column) if incident and incident_company_column else None)
        fact_type = fact_type_by_id.get(fact.get(fact_type_column))

        company_name = company.get(company_name_column) if company and company_name_column else None
        industry = first_present(company or {}, ["industry", "sector"])
        country = first_present(company or {}, ["country", "country_name", "region"])
        incident_date = incident.get(incident_date_column) if incident and incident_date_column else None
        fact_type_name = (
            fact_type.get(fact_type_name_column)
            if fact_type and fact_type_name_column
            else first_present(fact, ["fact_type", "type", "category"])
        )

        records.append(
            {
                "incident_id": incident.get(incident_id_column) if incident and incident_id_column else None,
                "fact_id": fact.get(fact_id_column),
                "fact_summary": fact.get(fact_summary_column) if fact_summary_column else summarize_fact(fact)["title"],
                "fact_status": first_present(fact, ["review_status", "approval_status", "fact_status", "status"]),
                "company_name": company_name,
                "industry": industry,
                "country": country,
                "incident_date": incident_date,
                "fact_type": fact_type_name,
            }
        )

    return records


def apply_research_filters(records, filters):
    filtered = []
    company_query = normalize_text(filters.get("company_name"))
    incident_date_query = str(filters.get("incident_date", "")).strip()
    industry_query = normalize_text(filters.get("industry"))
    country_query = normalize_text(filters.get("country"))
    fact_type_query = normalize_text(filters.get("fact_type"))

    for record in records:
        if company_query and company_query not in normalize_text(record.get("company_name")):
            continue
        if incident_date_query and incident_date_query not in str(record.get("incident_date") or ""):
            continue
        if industry_query and industry_query != normalize_text(record.get("industry")):
            continue
        if country_query and country_query != normalize_text(record.get("country")):
            continue
        if fact_type_query and fact_type_query != normalize_text(record.get("fact_type")):
            continue
        filtered.append(record)

    return filtered


def build_filter_options(records, key):
    options = sorted(
        {
            str(record.get(key)).strip()
            for record in records
            if record.get(key) not in (None, "")
        }
    )
    return options


def build_incident_spotlight_records(companies_columns, company_rows, incident_records, limit=6):
    company_id_column = choose_company_id_column(companies_columns)
    company_name_column = choose_company_name_column(companies_columns)
    companies_by_id = {}

    for company in rows_to_dicts(companies_columns, company_rows):
        companies_by_id[str(company.get(company_id_column))] = company

    spotlight = []
    for incident in incident_records[:limit]:
        company = companies_by_id.get(str(first_present(incident, ["company_id", "company"])))
        spotlight.append(
            {
                "incident_id": first_present(incident, ["incident_id", "id"]),
                "company_name": company.get(company_name_column) if company and company_name_column else "Unknown company",
                "incident_date": first_present(incident, ["incident_date", "discovered_at", "created_at"]),
                "status": first_present(incident, ["status", "incident_status"]),
                "country": first_present(company or {}, ["country", "country_name", "region"]),
                "industry": first_present(company or {}, ["industry", "sector"]),
            }
        )

    return spotlight


def attach_company_names_to_incidents(companies_columns, company_rows, incident_records):
    company_id_column = choose_company_id_column(companies_columns)
    company_name_column = choose_company_name_column(companies_columns)
    companies_by_id = {}

    for company in rows_to_dicts(companies_columns, company_rows):
        companies_by_id[str(company.get(company_id_column))] = (
            company.get(company_name_column) if company_name_column else None
        )

    enriched_records = []
    for incident in incident_records:
        incident_copy = dict(incident)
        company_id = first_present(incident_copy, ["company_id", "company"])
        incident_copy["company_name"] = companies_by_id.get(str(company_id))
        enriched_records.append(incident_copy)

    return enriched_records


def enrich_incident_rows_with_company_name(companies_columns, company_rows, incident_columns, incident_rows):
    incident_records = rows_to_dicts(incident_columns, incident_rows)
    enriched_records = attach_company_names_to_incidents(
        companies_columns,
        company_rows,
        incident_records,
    )

    company_id_column = choose_company_id_column(companies_columns)
    companies_by_id = {
        str(company.get(company_id_column)): company
        for company in rows_to_dicts(companies_columns, company_rows)
        if company_id_column and company.get(company_id_column) is not None
    }

    enriched_columns = list(incident_columns)
    if "company_name" not in enriched_columns:
        enriched_columns.append("company_name")
    if "cusip" not in enriched_columns:
        enriched_columns.append("cusip")

    enriched_rows = []
    for record in enriched_records:
        company = companies_by_id.get(str(first_present(record, ["company_id", "company"])))
        enriched_record = dict(record)
        enriched_record["cusip"] = first_present(company or {}, ["cusip", "CUSIP"])
        enriched_rows.append(tuple(enriched_record.get(column) for column in enriched_columns))
    return enriched_columns, enriched_rows


def build_incident_index_records(companies_columns, company_rows, incidents_columns, incident_rows):
    company_id_column = choose_company_id_column(companies_columns)
    company_name_column = choose_company_name_column(companies_columns)
    companies_by_id = {}

    for company in rows_to_dicts(companies_columns, company_rows):
        companies_by_id[str(company.get(company_id_column))] = company

    incident_records = rows_to_dicts(incidents_columns, incident_rows)
    indexed = []
    for incident in incident_records:
        company = companies_by_id.get(str(first_present(incident, ["company_id", "company"])))
        indexed.append(
            {
                "incident_id": first_present(incident, ["incident_id", "id"]),
                "company_name": company.get(company_name_column) if company and company_name_column else "Unknown company",
                "incident_date": first_present(incident, ["incident_date", "discovered_at", "created_at"]),
                "status": first_present(incident, ["status", "incident_status"]),
                "industry": first_present(company or {}, ["industry", "sector"]),
                "country": first_present(company or {}, ["country", "country_name", "region"]),
            }
        )

    indexed.sort(
        key=lambda record: parse_datetime_value(record.get("incident_date")) or datetime.min,
        reverse=True,
    )
    return indexed


def build_incident_selection_options(companies_columns, company_rows, incidents_columns, incident_rows):
    company_id_column = choose_company_id_column(companies_columns)
    company_name_column = choose_company_name_column(companies_columns)
    incident_id_column = choose_incident_id_column(incidents_columns)
    incident_date_column = choose_incident_date_column(incidents_columns)

    companies_by_id = {}
    for company in rows_to_dicts(companies_columns, company_rows):
        companies_by_id[str(company.get(company_id_column))] = company

    options = []
    for incident in rows_to_dicts(incidents_columns, incident_rows):
        incident_id = incident.get(incident_id_column)
        company = companies_by_id.get(str(first_present(incident, ["company_id", "company"])))
        company_name = company.get(company_name_column) if company and company_name_column else "Unknown company"
        incident_date = incident.get(incident_date_column) if incident_date_column else None
        label = company_name
        if incident_date:
            label = f"{company_name} ({incident_date})"
        options.append(
            {
                "id": incident_id,
                "label": label,
            }
        )

    return options


def apply_incident_filters(records, filters):
    company_query = normalize_text(filters.get("company_name"))
    incident_date_query = str(filters.get("incident_date", "")).strip()
    industry_query = normalize_text(filters.get("industry"))
    country_query = normalize_text(filters.get("country"))
    status_query = normalize_text(filters.get("status"))

    filtered = []
    for record in records:
        if company_query and company_query not in normalize_text(record.get("company_name")):
            continue
        if incident_date_query and incident_date_query not in str(record.get("incident_date") or ""):
            continue
        if industry_query and industry_query != normalize_text(record.get("industry")):
            continue
        if country_query and country_query != normalize_text(record.get("country")):
            continue
        if status_query and status_query != normalize_text(record.get("status")):
            continue
        filtered.append(record)

    return filtered


def current_role():
    if not has_request_context():
        return None
    return session.get("role")


def current_user():
    if not has_request_context():
        return {"user_id": None, "name": None, "email": None, "role": None}
    return {
        "user_id": session.get("user_id"),
        "name": session.get("user_name"),
        "email": session.get("user_email"),
        "role": session.get("role"),
    }


def has_required_role(required_role):
    user_role = current_role()
    if user_role not in ROLE_RANK or required_role not in ROLE_RANK:
        return False
    return ROLE_RANK[user_role] >= ROLE_RANK[required_role]


def role_label(role):
    return ROLE_LABELS.get(role, str(role).title() if role else "")


def admin_exists():
    try:
        count = query_scalar(
            """
            SELECT COUNT(*) AS admin_count
            FROM users
            WHERE LOWER(role) = 'admin'
            """
        )
    except psycopg2.OperationalError:
        return True
    return bool(count)


def password_hash_for_user(user):
    return first_present(user, ["password_hash", "password"])


def can_current_user_claim_admin():
    if not has_request_context():
        return False
    if not session.get("user_id") or not session.get("user_email"):
        return False
    return not admin_exists()


def require_login(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    return wrapped_view


def require_role(required_role):
    def decorator(view_func):
        @wraps(view_func)
        @require_login
        def wrapped_view(*args, **kwargs):
            if not has_required_role(required_role):
                flash("You do not have permission to access that page.", "danger")
                return redirect(url_for("dashboard"))
            return view_func(*args, **kwargs)

        return wrapped_view

    return decorator


@app.context_processor
def inject_auth_context():
    return {
        "current_user": current_user(),
        "current_role": current_role(),
        "role_labels": ROLE_LABELS,
        "role_label": role_label,
        "can_access": has_required_role,
        "can_claim_admin": can_current_user_claim_admin(),
    }


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form["email"].strip()
        password = request.form["password"]

        if not ensure_users_password_column():
            flash("Unable to verify password storage. Please check the database setup.", "danger")
            return render_template("login.html", email=email)

        ensure_signup_request_table()

        user = query_one(
            """
            SELECT *
            FROM users
            WHERE LOWER(email) = LOWER(%s)
            LIMIT 1
            """,
            (email,),
        )

        if not user:
            pending_request = query_one(
                """
                SELECT *
                FROM signup_request
                WHERE LOWER(email) = LOWER(%s)
                  AND status = 'pending'
                LIMIT 1
                """,
                (email,),
            )
            if pending_request:
                flash("Your signup request is still pending admin approval.", "warning")
                return render_template("login.html", email=email)
            rejected_request = query_one(
                """
                SELECT *
                FROM signup_request
                WHERE LOWER(email) = LOWER(%s)
                  AND status = 'rejected'
                ORDER BY reviewed_at DESC NULLS LAST, requested_at DESC
                LIMIT 1
                """,
                (email,),
            )
            if rejected_request:
                flash("Your signup request was rejected by an admin.", "danger")
                if rejected_request.get("review_comments"):
                    flash(
                        f"Admin note: {rejected_request['review_comments']}",
                        "warning",
                    )
                return render_template("login.html", email=email)
            flash("No user found with that email address.", "danger")
            return render_template("login.html", email=email)

        role = (user.get("role") or "").strip().lower()
        if role not in ROLE_RANK:
            flash("That user has an unsupported role.", "danger")
            return render_template("login.html", email=email)

        stored_password_hash = password_hash_for_user(user)
        if not stored_password_hash:
            execute_db(
                """
                UPDATE users
                SET password_hash = %s
                WHERE LOWER(email) = LOWER(%s)
                """,
                (generate_password_hash(password), email),
            )
            flash("Password set for your existing account. You are now logged in.", "success")
        elif not check_password_hash(stored_password_hash, password):
            flash("Incorrect password.", "danger")
            return render_template("login.html", email=email)

        user_id = first_present(user, ["user_id", "id"])
        display_name = first_present(user, ["name", "full_name", "email"])

        session.clear()
        session["user_id"] = user_id or user.get("email")
        session["user_name"] = display_name
        session["user_email"] = user.get("email")
        session["role"] = role

        flash("Logged in successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", email="")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        requested_role = request.form["requested_role"].strip().lower()

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template(
                "signup.html",
                name=name,
                email=email,
                requested_role=requested_role,
                role_options=list(ROLE_RANK.keys()),
            )

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template(
                "signup.html",
                name=name,
                email=email,
                requested_role=requested_role,
                role_options=list(ROLE_RANK.keys()),
            )

        if not ensure_users_password_column():
            flash("Unable to prepare password storage in the database.", "danger")
            return render_template(
                "signup.html",
                name=name,
                email=email,
                requested_role=requested_role,
                role_options=list(ROLE_RANK.keys()),
            )

        if not ensure_signup_request_table():
            flash("Unable to prepare signup request storage in the database.", "danger")
            return render_template(
                "signup.html",
                name=name,
                email=email,
                requested_role=requested_role,
                role_options=list(ROLE_RANK.keys()),
            )

        if requested_role not in ROLE_RANK:
            flash("Please select a valid requested role.", "danger")
            return render_template(
                "signup.html",
                name=name,
                email=email,
                requested_role=requested_role,
                role_options=list(ROLE_RANK.keys()),
            )

        existing_user = query_one(
            """
            SELECT *
            FROM users
            WHERE LOWER(email) = LOWER(%s)
            LIMIT 1
            """,
            (email,),
        )

        if existing_user:
            flash("An account with that email already exists. Please log in.", "warning")
            return redirect(url_for("login"))

        existing_request = query_one(
            """
            SELECT *
            FROM signup_request
            WHERE LOWER(email) = LOWER(%s)
              AND status = 'pending'
            LIMIT 1
            """,
            (email,),
        )
        if existing_request:
            flash("A pending signup request already exists for that email.", "warning")
            return redirect(url_for("login"))

        execute_db(
            """
            DELETE FROM signup_request
            WHERE LOWER(email) = LOWER(%s)
              AND status = 'rejected'
            """,
            (email,),
        )

        is_bootstrap_admin = not admin_exists()
        if is_bootstrap_admin:
            conn = psycopg2.connect(DATABASE_URL)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (name, email, role, password_hash) VALUES (%s, %s, %s, %s)",
                (name, email, "admin", generate_password_hash(password)),
            )
            conn.commit()
            cur.close()
            conn.close()

            flash(
                "Signup complete. No admin existed yet, so your account was bootstrapped as Admin.",
                "success",
            )
            return redirect(url_for("login"))

        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO signup_request (name, email, password_hash, requested_role)
            VALUES (%s, %s, %s, %s)
            """,
            (name, email, generate_password_hash(password), requested_role),
        )
        conn.commit()
        cur.close()
        conn.close()

        flash("Signup request submitted successfully.", "success")
        flash(
            "An admin must approve your requested {} role before your account is created.".format(
                requested_role.title()
            ),
            "info",
        )
        return redirect(url_for("login"))

    return render_template(
        "signup.html",
        name="",
        email="",
        requested_role="researcher",
        role_options=list(ROLE_RANK.keys()),
    )


# @app.route("/forgot-password", methods=["GET", "POST"])
# def forgot_password():
#     if request.method == "POST":
#         email = request.form["email"].strip()
#         if not ensure_password_reset_request_table():
#             flash("Unable to prepare password recovery right now. Please try again later.", "danger")
#             return render_template("forgot_password.html", email=email)

#         user = query_one(
#             """
#             SELECT *
#             FROM users
#             WHERE LOWER(email) = LOWER(%s)
#             LIMIT 1
#             """,
#             (email,),
#         )

#         if user:
#             existing_request = query_one(
#                 """
#                 SELECT *
#                 FROM password_reset_request
#                 WHERE LOWER(email) = LOWER(%s)
#                   AND status = 'pending'
#                 LIMIT 1
#                 """,
#                 (email,),
#             )
#             if existing_request:
#                 flash(
#                     "A password reset request is already pending for that account. An admin still needs to set a temporary password.",
#                     "info",
#                 )
#             else:
#                 execute_db(
#                     """
#                     INSERT INTO password_reset_request (email, name, status)
#                     VALUES (%s, %s, 'pending')
#                     ON CONFLICT (email)
#                     DO UPDATE SET
#                         name = EXCLUDED.name,
#                         status = 'pending',
#                         requested_at = NOW(),
#                         reviewed_at = NULL,
#                         reviewed_by = NULL
#                     """,
#                     (email, first_present(user, ["name", "full_name", "email"])),
#                 )
#                 flash(
#                     "Your password reset request has been sent to an admin. They can issue a temporary password from the Manage Users screen.",
#                     "success",
#                 )
#         else:
#             flash("No account found for that email address.", "danger")

#         return render_template("forgot_password.html", email=email)

#     return render_template("forgot_password.html", email="")

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"].strip()

        user = query_one(
            "SELECT * FROM users WHERE LOWER(email) = LOWER(%s) LIMIT 1",
            (email,),
        )

        if user:
            token = generate_reset_token(email)
            reset_link = url_for("reset_password", token=token, _external=True)

            msg = Message(
                "Password Reset Request",
                sender=app.config["MAIL_USERNAME"],
                recipients=[email]
            )
            msg.body = f"Click this link to reset your password:\n{reset_link}"

            mail.send(msg)

        # security: don't reveal if email exists
        flash("If the email exists, a reset link has been sent.", "info")
        return redirect(url_for("login"))

    return render_template("forgot_password.html", email="")

@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = verify_reset_token(token)

    if not email:
        flash("Invalid or expired reset link.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form["password"]

        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("reset_password.html")

        execute_db(
            "UPDATE users SET password_hash = %s WHERE LOWER(email) = LOWER(%s)",
            (generate_password_hash(new_password), email)
        )

        flash("Password updated successfully!", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.route("/claim-admin", methods=["POST"])
@require_login
def claim_admin():
    if admin_exists():
        flash("An admin already exists. Admin access can no longer be claimed automatically.", "danger")
        return redirect(url_for("dashboard"))

    user_email = session.get("user_email")
    if not user_email:
        flash("Unable to identify the current user.", "danger")
        return redirect(url_for("dashboard"))

    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE users
        SET role = 'admin'
        WHERE LOWER(email) = LOWER(%s)
        """,
        (user_email,),
    )
    conn.commit()
    cur.close()
    conn.close()

    session["role"] = "admin"
    flash("Your account has been promoted to Admin because no admin existed in the system.", "success")
    return redirect(url_for("dashboard"))

# @app.route("/")

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/dashboard")
@require_login
def dashboard():

    users_cols, users = query_db("SELECT * FROM users")
    companies_cols, companies = query_db("SELECT * FROM company")
    incidents_cols, incidents = query_db("SELECT * FROM incident")
    announcements_cols, announcements = query_db("SELECT * FROM announcement")
    sources_cols, sources = query_db("SELECT * FROM source")
    facts_cols, facts = query_db("SELECT * FROM fact")
    fact_type_cols, fact_types = query_db("SELECT * FROM fact_type")
    reviews_cols, reviews = query_db("SELECT * FROM fact_review")
    audit_cols, audit_logs = query_db("SELECT * FROM audit_log")

    companies_dicts = rows_to_dicts(companies_cols, companies)
    incidents_dicts = rows_to_dicts(incidents_cols, incidents)
    announcements_dicts = rows_to_dicts(announcements_cols, announcements)
    reviews_dicts = rows_to_dicts(reviews_cols, reviews)
    audit_logs_dicts = rows_to_dicts(audit_cols, audit_logs)

    stats = [
        {"label": "Total incidents", "value": len(incidents)},
        {"label": "Total companies", "value": len(companies)},
        {"label": "Total announcements", "value": len(announcements)},
        {"label": "Total facts", "value": len(facts)},
    ]

    recent_incidents = sort_recent_records(
        incidents_dicts,
        ["discovered_at", "incident_date", "created_at", "updated_at"],
    )
    recent_incidents = attach_company_names_to_incidents(
        companies_cols,
        companies,
        recent_incidents,
    )
    recent_announcements = sort_recent_records(
        announcements_dicts,
        ["announcement_date", "created_at", "updated_at"],
    )

    incident_preview_cols, incident_preview_rows = build_table_records_from_dicts(
        recent_incidents,
        ["incident_id", "company_name", "status", "incident_date", "created_at"],
    )
    company_preview_cols, company_preview_rows = build_table_records(
        companies_cols,
        companies,
        ["company_id", "company_name", "industry", "country"],
    )
    announcement_preview_cols, announcement_preview_rows = build_table_records_from_dicts(
        recent_announcements,
        ["announcement_id", "incident_id", "announcement_date", "source_id"],
    )

    quick_tables = [
        {
            "title": "Recent incidents",
            "columns": incident_preview_cols,
            "rows": incident_preview_rows,
        },
        {
            "title": "Company overview",
            "columns": company_preview_cols,
            "rows": company_preview_rows,
        },
        {
            "title": "Recent announcements",
            "columns": announcement_preview_cols,
            "rows": announcement_preview_rows,
        },
    ]

    recent_activity = build_recent_activity(
        recent_announcements,
        reviews_dicts,
        audit_logs_dicts,
    )
    incident_spotlights = build_incident_spotlight_records(
        companies_cols,
        companies,
        recent_incidents,
    )

    return render_template(
        "dashboard.html",
        users_cols=users_cols, users=users,
        companies_cols=companies_cols, companies=companies,
        incidents_cols=incidents_cols, incidents=incidents,
        announcements_cols=announcements_cols, announcements=announcements,
        sources_cols=sources_cols, sources=sources,
        facts_cols=facts_cols, facts=facts,
        fact_type_cols=fact_type_cols, fact_types=fact_types,
        reviews_cols=reviews_cols, reviews=reviews,
        audit_cols=audit_cols, audit_logs=audit_logs,
        stats=stats,
        quick_tables=quick_tables,
        recent_activity=recent_activity,
        incident_spotlights=incident_spotlights,
    )


@app.route("/data-viewer")
@require_login
def data_viewer():
    ensure_fact_type_table()
    ensure_company_cusip_column()
    users_cols, users = query_db("SELECT * FROM users")
    safe_users_cols, safe_users = strip_sensitive_columns(
        users_cols,
        users,
        {"password_hash", "password"},
    )
    companies_cols, companies = query_db("SELECT * FROM company")
    ordered_company_cols, ordered_companies = reorder_rows(
        companies_cols,
        companies,
        ["company_id", "cusip", "company_name"],
    )
    incidents_cols, incidents = query_db("SELECT * FROM incident")
    enriched_incident_cols, enriched_incident_rows = enrich_incident_rows_with_company_name(
        companies_cols,
        companies,
        incidents_cols,
        incidents,
    )
    visible_incident_cols, visible_incident_rows = strip_sensitive_columns(
        enriched_incident_cols,
        enriched_incident_rows,
        {"company_id", "company", "company_name"},
    )
    safe_incident_cols, safe_incident_rows = reorder_rows(
        visible_incident_cols,
        visible_incident_rows,
        ["incident_id", "cusip", "incident_date"],
    )
    announcements_cols, announcements = query_db("SELECT * FROM announcement")
    sources_cols, sources = query_db("SELECT * FROM source")
    facts_cols, facts = query_db("SELECT * FROM fact")
    fact_type_cols, fact_types = query_db("SELECT * FROM fact_type")
    enriched_fact_cols, enriched_fact_rows = enrich_fact_rows_with_type_details(
        facts_cols,
        facts,
        fact_type_cols,
        fact_types,
        users_cols,
        users,
    )
    safe_fact_cols, safe_fact_rows = hide_fact_type_id_from_fact_view(
        enriched_fact_cols,
        enriched_fact_rows,
    )

    viewer_tables = [
        build_data_view_table(
            "Users",
            safe_users_cols,
            safe_users,
            "Researcher and contributor accounts in the platform.",
        ),
        build_data_view_table(
            "Company",
            ordered_company_cols,
            ordered_companies,
            "Tracked victim organizations and their associated metadata.",
        ),
        build_data_view_table(
            "Incident",
            safe_incident_cols,
            safe_incident_rows,
            "Individual ransomware incidents under investigation.",
        ),
        build_data_view_table(
            "Announcement",
            announcements_cols,
            announcements,
            "Public disclosures, notices, and linked announcements.",
        ),
        build_data_view_table(
            "Source",
            sources_cols,
            sources,
            "Standardized source records used by announcements and evidence workflows.",
        ),
        build_data_view_table(
            "Fact Type",
            fact_type_cols,
            fact_types,
            "Reference table for fact type names and descriptions.",
        ),
        build_data_view_table(
            "Fact",
            safe_fact_cols,
            safe_fact_rows,
            "Atomic evidence records attached to the research workflow.",
        ),
    ]

    total_rows = sum(table["row_count"] for table in viewer_tables)

    return render_template(
        "data_viewer.html",
        viewer_tables=viewer_tables,
        total_rows=total_rows,
    )


@app.route("/research")
@require_login
def research_search():
    companies_cols, companies = query_db("SELECT * FROM company")
    incidents_cols, incidents = query_db("SELECT * FROM incident")
    facts_cols, facts = query_db("SELECT * FROM fact")
    fact_type_cols, fact_types = query_db("SELECT * FROM fact_type")

    base_records = build_research_records(
        {"columns": companies_cols, "records": rows_to_dicts(companies_cols, companies)},
        {"columns": incidents_cols, "records": rows_to_dicts(incidents_cols, incidents)},
        {"columns": facts_cols, "records": rows_to_dicts(facts_cols, facts)},
        {"columns": fact_type_cols, "records": rows_to_dicts(fact_type_cols, fact_types)},
    )

    filters = {
        "company_name": request.args.get("company_name", ""),
        "incident_date": request.args.get("incident_date", ""),
        "industry": request.args.get("industry", ""),
        "country": request.args.get("country", ""),
        "fact_type": request.args.get("fact_type", ""),
    }

    filtered_records = apply_research_filters(base_records, filters)

    return render_template(
        "research_search.html",
        filters=filters,
        records=filtered_records,
        total_records=len(filtered_records),
        filter_options={
            "industries": build_filter_options(base_records, "industry"),
            "countries": build_filter_options(base_records, "country"),
            "fact_types": build_filter_options(base_records, "fact_type"),
        },
    )


@app.route("/incidents")
@require_login
def incident_index():
    companies_cols, companies = query_db("SELECT * FROM company")
    incidents_cols, incidents = query_db("SELECT * FROM incident")

    filters = {
        "company_name": request.args.get("company_name", ""),
        "incident_date": request.args.get("incident_date", ""),
        "industry": request.args.get("industry", ""),
        "country": request.args.get("country", ""),
        "status": request.args.get("status", ""),
    }

    page = max(request.args.get("page", default=1, type=int), 1)
    per_page = 20

    base_records = build_incident_index_records(
        companies_cols,
        companies,
        incidents_cols,
        incidents,
    )
    filtered_records = apply_incident_filters(base_records, filters)

    total_records = len(filtered_records)
    total_pages = max((total_records + per_page - 1) // per_page, 1)
    if page > total_pages:
        page = total_pages

    start = (page - 1) * per_page
    end = start + per_page
    paginated_records = filtered_records[start:end]

    return render_template(
        "incident_index.html",
        filters=filters,
        records=paginated_records,
        total_records=total_records,
        page=page,
        total_pages=total_pages,
        filter_options={
            "industries": build_filter_options(base_records, "industry"),
            "countries": build_filter_options(base_records, "country"),
            "statuses": build_filter_options(base_records, "status"),
        },
    )


@app.route("/incident/<incident_id>")
@require_login
def incident_detail(incident_id):
    incident = build_incident_detail(incident_id)
    if not incident:
        flash("Incident not found.", "danger")
        return redirect(url_for("research_search"))

    return render_template("incident_detail.html", incident=incident)


@app.route("/incident/<incident_id>/edit", methods=["GET", "POST"])
@require_role("coder")
def edit_incident(incident_id):
    incidents_cols, incidents = query_db("SELECT * FROM incident")
    incident_records = rows_to_dicts(incidents_cols, incidents)
    identifier_column = choose_incident_id_column(incidents_cols)
    incident_record = next(
        (
            record
            for record in incident_records
            if str(record.get(identifier_column)) == str(incident_id)
        ),
        None,
    )

    if not incident_record:
        flash("Incident not found.", "danger")
        return redirect(url_for("incident_index"))

    form_config = build_dynamic_form(
        "incident",
        f"Edit Incident {incident_id}",
        "Update incident details and save changes directly from the incident detail workflow.",
    )

    submitted_values = {
        field["name"]: incident_record.get(field["name"], "")
        for field in form_config["fields"]
    }

    if request.method == "POST":
        submitted_values = request.form.to_dict()
        try:
            update_dynamic_record(
                "incident",
                form_config["fields"],
                request.form,
                identifier_column,
                incident_id,
            )
        except ValueError as exc:
            flash(str(exc), "danger")
        else:
            flash("Incident updated successfully.", "success")
            return redirect(url_for("incident_detail", incident_id=incident_id))

    return render_template(
        "entity_form.html",
        form_config=form_config,
        submitted_values=submitted_values,
    )


@app.route("/review-facts", methods=["GET", "POST"])
@require_role("reviewer")
def review_facts():
    fact_cols, fact_rows = query_db("SELECT * FROM fact ORDER BY 1 DESC")
    fact_records = rows_to_dicts(fact_cols, fact_rows)
    review_metadata = get_table_metadata("fact_review")
    review_columns = [column["column_name"] for column in review_metadata]
    latest_reviews = build_latest_reviews_by_fact()

    if request.method == "POST":
        fact_id = request.form["fact_id"].strip()
        decision = request.form["decision"].strip()
        comments = request.form["comments"].strip()

        if decision not in {"Approved", "Rejected"}:
            flash("Decision must be Approved or Rejected.", "danger")
            return redirect(url_for("review_facts"))

        try:
            payload = build_review_insert_payload(
                review_columns,
                fact_id,
                decision,
                comments,
                session.get("user_id"),
            )
            insert_record_from_payload("fact_review", payload)
            fact_status_updated = update_fact_status(fact_id, decision)
        except ValueError as exc:
            flash(str(exc), "danger")
        except psycopg2.Error as exc:
            flash(f"Unable to save fact review: {exc.pgerror or str(exc)}", "danger")
        else:
            if fact_status_updated:
                flash("Fact review submitted and fact status updated successfully.", "success")
            else:
                flash("Fact review submitted successfully. No compatible fact status column was found to update.", "warning")
        return redirect(url_for("review_facts"))

    fact_cards = []
    for record in fact_records:
        summary = summarize_fact(record)
        latest_review = latest_reviews.get(summary["id"], {})
        fact_cards.append(
            {
                "id": summary["id"],
                "title": summary["title"],
                "meta": summary["meta"],
                "current_status": summary["status"],
                "latest_decision": latest_review.get("decision"),
                "latest_comments": latest_review.get("comments"),
                "latest_timestamp": latest_review.get("timestamp"),
            }
        )

    return render_template(
        "review_facts.html",
        fact_cards=fact_cards,
    )


@app.route("/seed-sample-facts", methods=["POST"])
@require_role("coder")
def seed_sample_facts():
    try:
        payloads = build_sample_fact_payloads()
        for payload in payloads:
            insert_record_from_payload("fact", payload)
    except ValueError as exc:
        flash(str(exc), "danger")
    except psycopg2.Error as exc:
        flash(f"Unable to seed sample facts: {exc.pgerror or str(exc)}", "danger")
    else:
        flash("Sample facts added successfully. They are now available for review.", "success")

    return redirect(url_for("dashboard"))


@app.route("/manage-users", methods=["GET", "POST"])
@require_role("admin")
def manage_users():
    ensure_signup_request_table()
    ensure_password_reset_request_table()
    users_cols, users = query_db("SELECT * FROM users ORDER BY email")
    user_records = rows_to_dicts(users_cols, users)
    identifier_column = get_user_identifier_column(users_cols)

    if request.method == "POST":
        action = request.form.get("action")

        if action in {"approve_request", "reject_request"}:
            request_id = request.form["signup_request_id"]
            review_comments = request.form.get("review_comments", "").strip()
            signup_request = query_one(
                """
                SELECT *
                FROM signup_request
                WHERE signup_request_id = %s
                LIMIT 1
                """,
                (request_id,),
            )

            if not signup_request or signup_request.get("status") != "pending":
                flash("Signup request not found or already processed.", "warning")
                return redirect(url_for("manage_users"))

            if action == "approve_request":
                existing_user = query_one(
                    """
                    SELECT *
                    FROM users
                    WHERE LOWER(email) = LOWER(%s)
                    LIMIT 1
                    """,
                    (signup_request["email"],),
                )
                if existing_user:
                    flash("A user with that email already exists.", "danger")
                    return redirect(url_for("manage_users"))

                execute_db(
                    """
                    INSERT INTO users (name, email, role, password_hash)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        signup_request["name"],
                        signup_request["email"],
                        signup_request["requested_role"],
                        signup_request["password_hash"],
                    ),
                )
                execute_db(
                    """
                    UPDATE signup_request
                    SET status = 'approved',
                        review_comments = %s,
                        reviewed_at = NOW(),
                        reviewed_by = %s
                    WHERE signup_request_id = %s
                    """,
                    (review_comments or None, session.get("user_email"), request_id),
                )
                flash("Signup request approved and user account created.", "success")
                return redirect(url_for("manage_users"))

            execute_db(
                """
                UPDATE signup_request
                SET status = 'rejected',
                    review_comments = %s,
                    reviewed_at = NOW(),
                    reviewed_by = %s
                WHERE signup_request_id = %s
                """,
                (review_comments or None, session.get("user_email"), request_id),
            )
            flash("Signup request rejected.", "success")
            return redirect(url_for("manage_users"))

        if action in {"approve_password_reset", "reject_password_reset"}:
            reset_request_id = request.form["password_reset_request_id"]
            reset_request = query_one(
                """
                SELECT *
                FROM password_reset_request
                WHERE password_reset_request_id = %s
                LIMIT 1
                """,
                (reset_request_id,),
            )

            if not reset_request or reset_request.get("status") != "pending":
                flash("Password reset request not found or already processed.", "warning")
                return redirect(url_for("manage_users"))

            if action == "reject_password_reset":
                execute_db(
                    """
                    UPDATE password_reset_request
                    SET status = 'rejected',
                        reviewed_at = NOW(),
                        reviewed_by = %s
                    WHERE password_reset_request_id = %s
                    """,
                    (session.get("user_email"), reset_request_id),
                )
                flash("Password reset request dismissed.", "success")
                return redirect(url_for("manage_users"))

            new_password = request.form.get("new_password", "")
            if len(new_password) < 8:
                flash("Temporary password must be at least 8 characters long.", "danger")
                return redirect(url_for("manage_users"))

            execute_db(
                """
                UPDATE users
                SET password_hash = %s
                WHERE LOWER(email) = LOWER(%s)
                """,
                (generate_password_hash(new_password), reset_request["email"]),
            )
            execute_db(
                """
                UPDATE password_reset_request
                SET status = 'completed',
                    reviewed_at = NOW(),
                    reviewed_by = %s
                WHERE password_reset_request_id = %s
                """,
                (session.get("user_email"), reset_request_id),
            )
            flash("Temporary password saved and password reset request completed.", "success")
            return redirect(url_for("manage_users"))

        if not identifier_column:
            flash("Unable to determine the user identifier column.", "danger")
            return redirect(url_for("manage_users"))

        user_identifier = request.form["user_id"]
        new_role = request.form["role"].strip().lower()

        if new_role not in ROLE_RANK:
            flash("Please select a valid role.", "danger")
            return redirect(url_for("manage_users"))

        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET role = %s WHERE {} = %s".format(identifier_column),
            (new_role, user_identifier),
        )
        conn.commit()
        cur.close()
        conn.close()

        if str(session.get("user_id")) == str(user_identifier):
            session["role"] = new_role

        flash("User role updated successfully.", "success")
        return redirect(url_for("manage_users"))

    normalized_users = []
    for user in user_records:
        normalized_users.append(
            {
                "user_id": first_present(user, [identifier_column, "user_id", "id"]),
                "name": first_present(user, ["name", "full_name", "email"]),
                "email": user.get("email"),
                "role": (user.get("role") or "").strip().lower(),
            }
        )

    pending_requests = []
    request_cols, request_rows = query_db(
        """
        SELECT *
        FROM signup_request
        WHERE status = 'pending'
        ORDER BY requested_at ASC
        """
    )
    for signup_request in rows_to_dicts(request_cols, request_rows):
        pending_requests.append(
            {
                "signup_request_id": signup_request.get("signup_request_id"),
                "name": signup_request.get("name"),
                "email": signup_request.get("email"),
                "requested_role": signup_request.get("requested_role"),
                "requested_at": signup_request.get("requested_at"),
            }
        )

    password_reset_requests = []
    reset_cols, reset_rows = query_db(
        """
        SELECT *
        FROM password_reset_request
        WHERE status = 'pending'
        ORDER BY requested_at ASC
        """
    )
    for reset_request in rows_to_dicts(reset_cols, reset_rows):
        password_reset_requests.append(
            {
                "password_reset_request_id": reset_request.get("password_reset_request_id"),
                "name": reset_request.get("name"),
                "email": reset_request.get("email"),
                "requested_at": reset_request.get("requested_at"),
            }
        )

    return render_template(
        "manage_users.html",
        users=normalized_users,
        role_options=list(ROLE_RANK.keys()),
        pending_requests=pending_requests,
        password_reset_requests=password_reset_requests,
    )


@app.route("/add_company", methods=["GET", "POST"])
@require_role("coder")
def add_company():
    form_config = build_dynamic_form(
        "company",
        "Add Company",
        "Create a new company record in the research database.",
    )
    submitted_values = {}

    if request.method == "POST":
        submitted_values = request.form.to_dict()
        try:
            insert_dynamic_record("company", form_config["fields"], request.form)
        except ValueError as exc:
            flash(str(exc), "danger")
        else:
            flash("Company added successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template(
        "entity_form.html",
        form_config=form_config,
        submitted_values=submitted_values,
    )


@app.route("/add_incident", methods=["GET", "POST"])
@require_role("coder")
def add_incident():
    form_config = build_dynamic_form(
        "incident",
        "Add Incident",
        "Create a new incident record using the current incident schema.",
    )
    submitted_values = {}

    if request.method == "POST":
        submitted_values = request.form.to_dict()
        try:
            insert_dynamic_record("incident", form_config["fields"], request.form)
        except ValueError as exc:
            flash(str(exc), "danger")
        else:
            flash("Incident added successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template(
        "entity_form.html",
        form_config=form_config,
        submitted_values=submitted_values,
    )


@app.route("/add_fact", methods=["GET", "POST"])
@require_role("coder")
def add_fact():
    form_config = build_dynamic_form(
        "fact",
        "Add Fact",
        "Create a new fact record with the required evidence fields.",
    )
    submitted_values = {}

    if request.method == "POST":
        submitted_values = request.form.to_dict()
        try:
            insert_dynamic_record("fact", form_config["fields"], request.form)
        except ValueError as exc:
            flash(str(exc), "danger")
        else:
            flash("Fact added successfully.", "success")
            return redirect(url_for("dashboard"))

    return render_template(
        "entity_form.html",
        form_config=form_config,
        submitted_values=submitted_values,
    )


@app.route("/add_source", methods=["GET", "POST"])
@require_role("coder")
def add_source():
    form_config = build_dynamic_form(
        "source",
        "Add Source",
        "Create a new source entry so announcements can reuse a standardized source list.",
    )
    submitted_values = {}

    if request.method == "POST":
        submitted_values = request.form.to_dict()
        try:
            insert_dynamic_record("source", form_config["fields"], request.form)
        except ValueError as exc:
            flash(str(exc), "danger")
        else:
            flash("Source added successfully.", "success")
            return redirect(url_for("add_announcement"))

    return render_template(
        "entity_form.html",
        form_config=form_config,
        submitted_values=submitted_values,
    )

@app.route("/add_user", methods=["GET", "POST"])
@require_role("admin")
def add_user():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        role = request.form["role"].strip().lower()
        password = request.form["password"]

        if role not in ROLE_RANK:
            flash("Role must be researcher, reviewer, coder, or admin.", "danger")
            return render_template("add_user.html", role_options=list(ROLE_RANK.keys()))

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("add_user.html", role_options=list(ROLE_RANK.keys()))

        if not ensure_users_password_column():
            flash("Unable to prepare password storage in the database.", "danger")
            return render_template("add_user.html", role_options=list(ROLE_RANK.keys()))

        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        cur.execute(
            "INSERT INTO users (name, email, role, password_hash) VALUES (%s, %s, %s, %s)",
            (name, email, role, generate_password_hash(password))
        )

        conn.commit()
        cur.close()
        conn.close()

        flash("User added successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_user.html", role_options=list(ROLE_RANK.keys()))

@app.route("/add_announcement", methods=["GET", "POST"])
@require_role("coder")
def add_announcement():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    companies_cols, companies = query_db("SELECT * FROM company")
    incidents_cols, incidents = query_db("SELECT * FROM incident")
    incident_options = build_incident_selection_options(
        companies_cols,
        companies,
        incidents_cols,
        incidents,
    )

    sources_cols, sources = query_db("SELECT * FROM source")
    source_id_column = choose_source_id_column(sources_cols)
    source_name_column = choose_source_name_column(sources_cols)
    source_records = rows_to_dicts(sources_cols, sources)

    if request.method == "POST":

        incident_id = request.form["incident_id"]
        source_name = request.form["source_name"].strip()
        url = request.form["url"]
        announcement_date = request.form["announcement_date"]
        content = request.form["content"]

        source_record = next(
            (
                source
                for source in source_records
                if normalize_text(source.get(source_name_column)) == normalize_text(source_name)
            ),
            None,
        )
        if not source_record:
            flash("Please choose a source that exists in the source table, or add a new source first.", "danger")
            cur.close()
            conn.close()
            return render_template(
                "add_announcement.html",
                incidents=incident_options,
                sources=source_records,
                selected_incident_id=incident_id,
                source_name=source_name,
                url=url,
                announcement_date=announcement_date,
                content=content,
            )

        source_id = source_record.get(source_id_column)

        cur.execute(
            """
            INSERT INTO announcement 
            (incident_id, source_id, url, announcement_date, content)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (incident_id, source_id, url, announcement_date, content)
        )

        conn.commit()

        cur.close()
        conn.close()

        flash("Announcement added successfully.", "success")
        return redirect(url_for("dashboard"))

    cur.close()
    conn.close()

    return render_template(
        "add_announcement.html",
        incidents=incident_options,
        sources=source_records,
        selected_incident_id="",
        source_name="",
        url="",
        announcement_date="",
        content="",
    )

if __name__ == "__main__":
    # app.run(debug=True)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
