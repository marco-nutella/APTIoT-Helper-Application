import flet as ft
import base64
import io
import os
from docx import Document

class FinalView:
    def __init__(self, page):
        self.page = page
        self.next_button = ft.Button("Close Application", on_click=self.close_application, style=ft.ButtonStyle(
                        color={
                            ft.ControlState.HOVERED: ft.Colors.WHITE,
                            ft.ControlState.DEFAULT: ft.Colors.BLACK,
                        },
                        bgcolor={
                            ft.ControlState.HOVERED: ft.Colors.GREEN_100,
                            ft.ControlState.DEFAULT: ft.Colors.GREEN_400,
                        },
                    ))

    async def close_application(self):
        await self.page.window.close()

    def populate(self):
            return ft.Container(
                alignment = ft.Alignment.TOP_LEFT,
                content= ft.Column(
                    margin = 15,
                    spacing = 15,
                    controls=[
                        ft.Row(
                            controls=[
                            ft.Text("All Done Now!", size=36, weight=ft.FontWeight.W_800),
                            ]
                        ),
                        ft.Column(
                            scroll = ft.ScrollMode.AUTO,
                            alignment=ft.MainAxisAlignment.START,
                            expand = True,
                            controls=[
                                ft.Text(value="Please Read...", expand=True, size=24, weight=ft.FontWeight.W_600),
                                ft.Text(value="""Thank you for using this framework! All documents, for each step of APTIoT, should have been automatically generated in your selected folder. Due to a
current technological limitation, the application must restart before another penetration test may be started. You may close it manually, or do so by clicking the button below. 
The application will not automatically restart."""
                                , size=16, weight=ft.FontWeight.W_400, text_align=ft.TextAlign.LEFT), # """ Breaks spacing in the string, so these lines needs to break identation.
                            ]
                        ),
                        self.next_button
                    ]
                )
            )