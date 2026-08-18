import flet as ft
import math
from abc import abstractmethod
from src.ivssutilities import IVSSSeveritiesMap, IVSSCalculator, IVSSStringVectorUtil, CVSSSampleGroups

class IVSSCategory:
    category_name = ""
    source_group = {"": 0}

    def __init__(self, name:str, source_group:dict[str, float], parent):
        self.category_name = name
        self.source_group = source_group
        self.parent = parent
        self.weight_value = 100
        self.slider_weight = ft.Text(value=f"Weight: {round(self.weight_value)}%", size=14, weight=ft.FontWeight.W_400)

    def get_options(self) -> list[ft.DropdownOption]:
        return [
            ft.DropdownOption(
                key = severity,
                content = ft.Text(value=severity, size=14, weight=ft.FontWeight.W_400)
            )
            for severity in IVSSSeveritiesMap.mappings[self.category_name].keys()
        ]

    def on_select_severity(self, event: ft.Event[ft.Dropdown]):
        self.source_group[self.category_name] = IVSSSeveritiesMap.mappings[self.category_name][event.control.value] # type: ignore
        self.parent.update_widget()

    def on_slider_change(self, event: ft.Event[ft.Slider]):
        if not event.control.value:
            return
        self.weight_value = event.control.value
        self.slider_weight.value = f"Weight: {round(self.weight_value)}%"
        self.slider_weight.update()
        self.parent.on_weight_change(self.category_name, self.weight_value/100)

    def populate(self):
        return ft.Column(
            controls= [
                ft.Text(self.category_name, expand=True, size=24, weight=ft.FontWeight.W_600),
                ft.Dropdown(
                    width = 400,
                    key = str.lower(self.category_name) + "_dropdown",
                    label = "Select...",
                    options = self.get_options(),
                    on_select = self.on_select_severity
                ),
                self.slider_weight,
                ft.Slider(min=0, max=200, divisions=20, value=self.weight_value, on_change=self.on_slider_change)
            ]
        )

class IVSSWidget():
    colors = [
        "#b9e2ff",
        "#00eeae",
        "#44ee00",
        "#a6ee00",
        "#deee00",
        "#ffed00",
        "#ffc400",
        "#ff9a00",
        "#ff0003",
        "#a00002",
        "#5a0001"
    ]

    def __init__(self, impact_group:dict[str, float], exposure_group:dict[str, float], weights:dict[str, float]):
        self.ivss_score = ft.Text(value="", size=56, weight=ft.FontWeight.W_700, text_align=ft.TextAlign.CENTER)
        self.ivss_text = ft.Text(value="", size=38, weight=ft.FontWeight.W_600, text_align=ft.TextAlign.CENTER)
        self.ivss_color = ft.Container(width=200, height=200, bgcolor=IVSSWidget.colors[0], border_radius=100)
        self.weighted_ivss_score = ft.Text(value="", size=14, weight=ft.FontWeight.W_400)
        self.ivss_str = ft.Text(value="", size=14, weight=ft.FontWeight.W_600)

        self.update_widget(impact_group, exposure_group, weights)

    def update_widget(self, impact_group, exposure_group, weights, startup = True):
        self.ivss = IVSSCalculator.get_ivss_score(impact_group, exposure_group)
        self.weighted_ivss = IVSSCalculator.get_weighted_ivss_score(impact_group, exposure_group, weights)
        self.ivss_score.value = str(self.ivss[0])
        self.ivss_text.value = IVSSStringVectorUtil.string(self.ivss[0], False)
        self.ivss_color.bgcolor = IVSSWidget.get_color_from_score(self.ivss[0])
        self.weighted_ivss_score.value = f"Weighted IVSS Score: {str(self.weighted_ivss[0])} ({IVSSStringVectorUtil.string(self.weighted_ivss[0], False)} Risk)"
        self.ivss_str.value = "IVSS Vector String: " + self.ivss[1]

        if not startup:
            self.ivss_score.update()
            self.ivss_text.update()
            self.ivss_color.update()
            self.weighted_ivss_score.update()
            self.ivss_str.update()

    def update_widget_from_score(self, given_score:tuple[float, str]):
        self.ivss = given_score
        self.weighted_ivss = given_score
        self.ivss_score.value = str(self.ivss[0])
        self.ivss_text.value = IVSSStringVectorUtil.string(self.ivss[0], False)
        self.ivss_color.bgcolor = IVSSWidget.get_color_from_score(self.ivss[0])
        self.weighted_ivss_score.value = f"Weighted IVSS Score: {str(self.weighted_ivss[0])} ({IVSSStringVectorUtil.string(self.weighted_ivss[0], False)} Risk)"
        self.ivss_str.value = "IVSS Vector String: " + self.ivss[1]

        self.ivss_score.update()
        self.ivss_text.update()
        self.ivss_color.update()
        self.weighted_ivss_score.update()
        self.ivss_str.update()

    @staticmethod
    def get_color_from_score(ivss_score:float) -> str:
        rounded_score = math.floor(ivss_score)
        return IVSSWidget.colors[rounded_score]

    def populate(self, show_weight:bool = True):
        self.weighted_ivss_score.visible = show_weight
        return ft.Column(
            alignment=ft.MainAxisAlignment.CENTER,
            controls=[
                ft.Row(
                    controls=[
                        ft.Stack(
                            alignment=ft.Alignment.CENTER,
                            controls=[
                                self.ivss_color,
                                ft.Column(
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=-17,
                                    controls=[
                                        self.ivss_score,
                                        self.ivss_text
                                    ]
                                )
                            ]
                        )
                    ]
                ),
                ft.Row(
                    alignment=ft.MainAxisAlignment.CENTER,
                    controls=[
                        self.weighted_ivss_score
                    ]
                ),
                ft.Row(
                    alignment=ft.MainAxisAlignment.CENTER,
                    controls=[
                        self.ivss_str
                    ]
                )
            ]
        )

class IVSSMainTab:
    def __init__(self, page):
        self.page = page
        self.impact_group = CVSSSampleGroups.impact_group.copy()
        self.exposure_group = CVSSSampleGroups.exposure_group.copy()
        self.weights = {
            "Confidentiality": 1.0,
            "Integrity": 1.0,
            "Availability": 1.0,
            "Authentication": 1.0,
            "Non-Repudiation": 1.0,
            "Access": 1.0,
            "Complexity": 1.0,
            "Safety": 1.0,
        }

        self.ivss_widget = IVSSWidget(self.impact_group, self.exposure_group, self.weights)
        self.cvss_ivss_widget = IVSSWidget(self.impact_group, self.exposure_group, self.weights)

    def update_widget(self):
        self.ivss_widget.update_widget(self.impact_group, self.exposure_group, self.weights, False)

    def on_weight_change(self, category:str, new_weight:float):
        self.weights[category] = new_weight
        self.update_widget()

    async def ivss_str_to_clipboard(self):
        ivss_vector_string = IVSSStringVectorUtil.get_ivss_str(self.impact_group, self.exposure_group)
        await ft.Clipboard().set(ivss_vector_string)
        self.page.show_dialog(ft.SnackBar("Text copied to clipboard"))

    def on_enter_cvss_vector_string(self, event:ft.Event[ft.TextField]):
        self.cvss_ivss_widget.update_widget_from_score(IVSSCalculator.get_ivss_score_from_cvss_vector(event.control.value))

    def populate(self) -> ft.Container:
        return ft.Container(
            alignment = ft.Alignment.CENTER,
            content= ft.Tabs(
                length=2,
                expand=True,
                content=ft.Column(
                    controls = [
                        ft.TabBar(
                            secondary=True,
                            tabs=[
                                ft.Tab(label=ft.Text("Vulnerability Score Calculator")),
                                ft.Tab(label=ft.Text("CVSS to IVSS Converter"))
                            ]
                        ),
                        ft.TabBarView(
                            expand=True,
                            controls=[
                                ft.Row(
                                    spacing = 10,
                                    controls=[
                                        ft.Column(
                                            margin = 15,
                                            spacing = 15,
                                            scroll = ft.ScrollMode.AUTO,
                                            controls = [
                                                ft.Row(
                                                    controls=[
                                                        ft.Text("Impact Group", size=36, weight=ft.FontWeight.W_800),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Confidentiality", self.impact_group, self).populate(),
                                                        IVSSCategory("Integrity", self.impact_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Availability", self.impact_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        ft.Text("Exposure Group", size=36, weight=ft.FontWeight.W_800),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Authentication", self.exposure_group, self).populate(),
                                                        IVSSCategory("Non-Repudiation", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Access", self.exposure_group, self).populate(),
                                                        IVSSCategory("Complexity", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START,
                                                    spacing = 50,
                                                ),
                                                ft.Row(
                                                    controls=[
                                                        IVSSCategory("Safety", self.exposure_group, self).populate(),
                                                    ],
                                                    alignment=ft.MainAxisAlignment.START
                                                ),
                                            ]
                                        ),
                                        ft.Column(
                                            margin = 15,
                                            spacing = 15,
                                            controls = [
                                                self.ivss_widget.populate(),
                                                ft.Button("Copy to clipboard", on_click=self.ivss_str_to_clipboard),
                                            ]
                                        )
                                    ],
                                ),
                                ft.Row(
                                    controls=[
                                        ft.Column(
                                            alignment=ft.MainAxisAlignment.CENTER,
                                            margin=15,
                                            controls=[
                                                self.cvss_ivss_widget.populate(False),
                                                ft.Button("Copy to clipboard", on_click=self.ivss_str_to_clipboard)
                                            ]
                                        ),
                                        ft.TextField(label="CVSS Vector String", hint_text="Enter a CVSS Vector String here...", on_submit=self.on_enter_cvss_vector_string)
                                    ],
                                    alignment=ft.MainAxisAlignment.CENTER
                                ),
                            ]
                        )
                    ]
                )
            )
        )
    