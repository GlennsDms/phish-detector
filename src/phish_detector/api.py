import os
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import tempfile

from phish_detector.parser import parse_eml
from phish_detector.features import extract_features
from phish_detector.model import predict
from phish_detector.integrations import enrich_parsed_email

app = FastAPI(
    title="Phish Detector",
    description="API for analyzing .eml files and detecting phishing emails.",
    version="0.1.0",
)

MODEL_PATH = Path(os.getenv("MODEL_PATH", "models/phish_detector.joblib"))


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": MODEL_PATH.exists()}


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    enrich: bool = False,
):
    if not file.filename.endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are supported.")

    if not MODEL_PATH.exists():
        raise HTTPException(
            status_code=503,
            detail=f"Model not found at {MODEL_PATH}. Train the model first."
        )

    # Save upload to temp file
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
            contents = await file.read()
            tmp.write(contents)
            tmp_path = Path(tmp.name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read file: {e}")

    try:
        parsed = parse_eml(tmp_path)
        features = extract_features(parsed)
        result = predict(features, MODEL_PATH)

        response = {
            "verdict": result["verdict"],
            "confidence": result["confidence"],
            "probabilities": result["probabilities"],
            "features": features,
            "email": {
                "subject": parsed.get("subject"),
                "from": parsed.get("from"),
                "reply_to": parsed.get("reply_to"),
                "url_count": len(parsed.get("urls", [])),
                "attachment_count": len(parsed.get("attachments", [])),
            },
        }

        if enrich:
            response["enrichment"] = enrich_parsed_email(parsed)

        return JSONResponse(content=response)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        tmp_path.unlink(missing_ok=True)


@app.post("/analyze/batch")
async def analyze_batch(files: list[UploadFile] = File(...)):
    if len(files) > 20:
        raise HTTPException(status_code=400, detail="Maximum 20 files per batch.")

    results = []
    for file in files:
        if not file.filename.endswith(".eml"):
            results.append({"file": file.filename, "error": "Not an .eml file"})
            continue

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as tmp:
                contents = await file.read()
                tmp.write(contents)
                tmp_path = Path(tmp.name)

            parsed = parse_eml(tmp_path)
            features = extract_features(parsed)
            result = predict(features, MODEL_PATH)

            results.append({
                "file": file.filename,
                "verdict": result["verdict"],
                "confidence": result["confidence"],
            })

        except Exception as e:
            results.append({"file": file.filename, "error": str(e)})

        finally:
            tmp_path.unlink(missing_ok=True)

    return JSONResponse(content={"results": results})