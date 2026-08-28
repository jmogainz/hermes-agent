"""Additional stream-boundary tests for the native component filter."""

from agent.native_component_protocol import NativeComponentStreamFilter
from run_agent import AIAgent


def test_stream_filter_preserves_text_around_marker():
    stream = NativeComponentStreamFilter()
    assert stream.feed("hello ") == "hello "
    assert stream.feed("<semreh.native-component>{}") == ""
    assert stream.feed("</semreh.native-component> world") == " world"


def test_agent_fire_stream_delta_hides_marker_chunks():
    agent = AIAgent.__new__(AIAgent)
    agent._stream_writer_superseded = lambda: False
    agent._stream_writer_is_current = lambda _: True
    agent._stream_think_scrubber = None
    agent._stream_context_scrubber = None
    agent._current_streamed_assistant_text = ""
    agent._stream_needs_break = False
    agent.stream_delta_callback = lambda text: received.append(text)
    agent._stream_callback = None
    agent._stream_writer_tls = None
    agent._note_dropped_stream_writer = lambda _: None
    received = []

    agent._fire_stream_delta("Before <semreh.native-component>")
    agent._fire_stream_delta('{"type":"semreh.native-component.v1"}')
    agent._fire_stream_delta("</semreh.native-component>After")

    assert received == ["Before ", "After"]
