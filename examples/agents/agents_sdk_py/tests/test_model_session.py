import os
import unittest
from unittest.mock import patch

import httpx
from agents import OpenAIResponsesModel, RunConfig, Runner
from openai import AsyncOpenAI


class ModelSessionTest(unittest.IsolatedAsyncioTestCase):
    async def test_model_request_carries_the_demo_capability_session(self):
        requests = []

        def respond(request):
            requests.append(request)
            return httpx.Response(
                200,
                json={
                    "id": "resp_fixture",
                    "object": "response",
                    "created_at": 0,
                    "model": "gpt-4.1",
                    "status": "completed",
                    "output": [
                        {
                            "id": "msg_fixture",
                            "type": "message",
                            "role": "assistant",
                            "status": "completed",
                            "content": [
                                {
                                    "type": "output_text",
                                    "text": "fixture response",
                                    "annotations": [],
                                }
                            ],
                        }
                    ],
                },
            )

        with patch.dict(os.environ, {"FIRMA_SESSION_ID": "fixture-session"}):
            from agent.main import agent

            async with AsyncOpenAI(
                api_key="fixture-key",
                http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
            ) as client:
                fixture_agent = agent.clone(
                    model=OpenAIResponsesModel(model="gpt-4.1", openai_client=client)
                )
                result = await Runner.run(
                    fixture_agent,
                    "Return the fixture response.",
                    run_config=RunConfig(tracing_disabled=True),
                )

        self.assertEqual(result.final_output, "fixture response")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].url.path, "/v1/responses")
        self.assertEqual(requests[0].headers.get("x-firma-session-id"), "fixture-session")
