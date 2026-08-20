import flet as ft
#from functools import partial
from src.idsesutilities import Protocols, RiskEnvironment, RiskCriticality, RiskAcceptance
from src.ivsscalculator import IVSSMainTab, IVSSWidget
from src.ivssutilities import IVSSStringVectorUtil
from src.ivssvulnerability import IVSSVulnerability

class IDSESDevice:
    def __init__(self, name:str = "Unnamed", manufacturer:str = "N/A", year:int = 1970):
        self.protocols = {}
        self.vulnerabilities = {}
        self.vulnerability_protocols = {}
        self.risk_environment = RiskEnvironment.PERSONAL
        self.risk_criticality = RiskCriticality.LOW
        self.score = 0.0
        self.weighted_score = 0.0
        self.update_information(name, manufacturer, year)

    def update_information(self, name:str = "", manufacturer:str = "", year:int = 0, risk_environment:RiskEnvironment = RiskEnvironment.PERSONAL, risk_criticality:RiskCriticality = RiskCriticality.LOW):
        if name:
            self.name = name
        if manufacturer:
            self.vendor = manufacturer
        if year:
            self.year = year

    def update_risk_environment(self, risk_environment:RiskEnvironment):
        self.risk_environment = risk_environment

    def update_risk_criticality(self, risk_criticality:RiskCriticality):
        self.risk_criticality = risk_criticality

    def add_protocol(self, protocol:Protocols):
        self.protocols[protocol] = protocol.value

    def add_vulnerability(self, vulnerability:IVSSVulnerability):
        protocol = vulnerability.get_protocol()
        if not protocol in self.vulnerability_protocols:
            self.vulnerability_protocols[protocol] = 0
        self.vulnerability_protocols[protocol] += 1
        vulnerability.set_id(self.vulnerability_protocols[protocol])
        self.vulnerabilities[vulnerability.get_name()] = vulnerability

    def remove_protocol(self, protocol:Protocols):
        if protocol in self.protocols:
            del self.protocols[protocol]

    def remove_vulnerability(self, vulnerability:IVSSVulnerability):
        vuln_name = vulnerability.get_name()
        if vuln_name in self.vulnerabilities:
                del self.vulnerabilities[vuln_name]

    def get_protocol_scores(self) -> list[float]:
        result = []
        for p in self.protocols.values():
            result.append(p[1])
        return result

    def get_vulnerability_scores(self, use_weighted_scores:bool=False) -> list[float]:
        result = []
        for v in self.vulnerabilities.values():
            score = v.get_weighted_score() if use_weighted_scores else v.get_score()
            result.append(score[0])
        return result

    @staticmethod
    def get_metrics_group_score(metrics_group:list[int|float]) -> float:
        if not len(metrics_group):
            return 0.0

        if len(metrics_group) == 1:
            return metrics_group[0]

        maxN = max(metrics_group)

        new_group = metrics_group.copy()
        new_group.remove(maxN)

        score = (maxN+(sum(new_group)/len(new_group)))/2
        return round(score, 1)

    def get_idses_score(self) -> tuple[float, str]:
        protocols_score = IDSESDevice.get_metrics_group_score(self.get_protocol_scores())
        vulnerabilities_score = IDSESDevice.get_metrics_group_score(self.get_vulnerability_scores())
        self.score = min(round(IDSESDevice.get_metrics_group_score([protocols_score, vulnerabilities_score]), 1), 10)
        return (self.score, IVSSStringVectorUtil.string(self.score, False))

    def get_weighted_idses_score(self) -> tuple[float, str]:
        protocols_score = IDSESDevice.get_metrics_group_score(self.get_protocol_scores())
        vulnerabilities_score = IDSESDevice.get_metrics_group_score(self.get_vulnerability_scores(True))
        weighted_score = IDSESDevice.get_metrics_group_score([protocols_score, vulnerabilities_score])
        if self.risk_environment:
            weighted_score *= self.risk_environment.value[1]
        if self.risk_criticality:
            weighted_score *= self.risk_criticality.value[1]

        self.weighted_score = min(round(weighted_score,1), 10)
        return (self.weighted_score, IVSSStringVectorUtil.string(self.weighted_score, False))

    def get_recommended_risk_acceptance(self) -> float:
        return RiskAcceptance.matrix[self.risk_environment][self.risk_criticality]

    def validate_score_with_risk(self) -> bool:
        return self.score <= RiskAcceptance.matrix[self.risk_environment][self.risk_criticality]

class IDSESWidget(): # This is where the IVSSVulnerability "lives".
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

    def __init__(self, device:IDSESDevice):
        self.idses_score = ft.Text(value="", size=56, weight=ft.FontWeight.W_700, text_align=ft.TextAlign.CENTER)
        self.idses_text = ft.Text(value="", size=38, weight=ft.FontWeight.W_600, text_align=ft.TextAlign.CENTER)
        self.idses_color = ft.Container(width=200, height=200, bgcolor=IVSSWidget.colors[0], border_radius=100)
        self.device = device

        self.update_widget()

    def update_widget(self, startup = True, use_weighted = False):
        self.device_score = self.device.get_weighted_idses_score() if use_weighted else self.device.get_idses_score()
        self.idses_score.value = str(self.device_score[0])
        self.idses_text.value = self.device_score[1]
        self.idses_color.bgcolor = IVSSWidget.get_color_from_score(self.device_score[0]) # IDSES uses the same color palette as IVSS.

        if not startup:
            self.idses_score.update()
            self.idses_text.update()
            self.idses_color.update()

    def populate(self):
        return ft.Column(
            alignment=ft.MainAxisAlignment.CENTER,
            controls=[
                ft.Row(
                    controls=[
                        ft.Stack(
                            alignment=ft.Alignment.CENTER,
                            controls=[
                                self.idses_color,
                                ft.Column(
                                    alignment=ft.MainAxisAlignment.CENTER,
                                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                                    spacing=-17,
                                    controls=[
                                        self.idses_score,
                                        self.idses_text
                                    ]
                                )
                            ]
                        )
                    ]
                ),
            ]
        )


class IDSESMainTab:
    def __init__(self, page):
        self.page = page
        self.device = IDSESDevice()
        self.checkboxes = []
        self.vulnerability_widgets = []
        self.ivss_main_tab = IVSSMainTab(page, True)
        self.ivss_editor = self.ivss_main_tab.populate()

        self.name_input = ft.TextField(label="Device Name", hint_text="Ente the device's name here...", width=400, on_change=self.on_change_device_name)
        self.vendor_input = ft.TextField(label="Vendor Name", hint_text="Enter the device's vendor here...", width=400, multiline=True, min_lines=1, max_lines=10, on_change=self.on_change_device_vendor)
        self.year_input = ft.TextField(label="Enter Year", hint_text="...", width=100, on_change=self.on_change_device_year,
                        input_filter=ft.InputFilter(
                            regex_string=r"^\d+$",
                            allow=True,
                            replacement_string=""
                        )
                    )


        self.environment_dropdown = ft.Dropdown(
                                width = 300,
                                key = "environment_dropdown",
                                label = "Select...",
                                options = [
                                    ft.DropdownOption(
                                        key = env.value[0],
                                        content = ft.Text(value=env.value[0], size=14, weight=ft.FontWeight.W_400),
                                    )
                                    for env in RiskEnvironment
                                ],
                                on_select = self.on_select_environment
                            )

        self.criticality_dropdown = ft.Dropdown(
                                width = 300,
                                key = "environment_dropdown",
                                label = "Select...",
                                options = [
                                    ft.DropdownOption(
                                        key = env.value[0],
                                        content = ft.Text(value=env.value[0], size=14, weight=ft.FontWeight.W_400),
                                    )
                                    for env in RiskCriticality
                                ],
                                on_select = self.on_select_criticality
                            )
        self.risk_acceptance_preamble = ft.Text(value=f"Your recommended highest acceptable risk: {self.device.get_recommended_risk_acceptance()}", expand=True, size=24, weight=ft.FontWeight.W_600),
        self.risk_acceptance_result = ft.Text(value="This device is acceptable for your recommended risk level.", expand=True, size=18, weight=ft.FontWeight.W_500, color=ft.Colors.GREEN_400),
        
        self.main_idses_widget = IDSESWidget(self.device)
        self.weighted_idses_weidget = IDSESWidget(self.device)
        #self.weighted_checkbox = ft.Checkbox(label="Use weighted IVSS scores", value=False)

        for p in Protocols: 
            self.checkboxes.append(ft.Checkbox(label=p.value[0], value=False, data=p, on_change=self.on_change_device_protocols))

    def update_widgets(self):
        self.main_idses_widget.update_widget(False)
        self.weighted_idses_weidget.update_widget(False, True)
        self.risk_acceptance_preamble[0].value = f"Your recommended highest acceptable risk: {self.device.get_recommended_risk_acceptance()}"
        if not self.device.validate_score_with_risk():
            self.risk_acceptance_result[0].value = "This device is NOT acceptable for your recommended risk level."
            self.risk_acceptance_result[0].color = ft.Colors.RED_400
        else:
            self.risk_acceptance_result[0].value = "This device is acceptable for your recommended risk level."
            self.risk_acceptance_result[0].color = ft.Colors.GREEN_400
        self.page.update()

    def on_change_device_protocols(self, event:ft.Event[ft.Checkbox]):
        if event.control.value:
            self.device.add_protocol(event.control.data)
        else:
            self.device.remove_protocol(event.control.data)
        self.update_widgets()

    def on_add_vulnerability_prompt(self):
        vulnerability = self.ivss_main_tab.export_vulnerability_and_reset_calculator()
        self.device.add_vulnerability(vulnerability)
        self.vulnerability_widgets.append(IVSSWidget(vulnerability=vulnerability).create_widget(self.page))
        self.update_widgets()
        self.page.update()

    def on_change_device_name(self, event:ft.Event[ft.TextField]):
        self.device.update_information(name=event.control.value)

    def on_change_device_vendor(self, event:ft.Event[ft.TextField]):
        self.device.update_information(manufacturer=event.control.value)

    def on_change_device_year(self, event:ft.Event[ft.TextField]):
        self.device.update_information(year=int(event.control.value))

    def on_select_environment(self, event:ft.Event[ft.Dropdown]):
        value = str(event.control.value).upper()
        self.device.update_risk_environment(RiskEnvironment[value])
        self.update_widgets()

    def on_select_criticality(self, event:ft.Event[ft.Dropdown]):
        value = str(event.control.value).upper()
        self.device.update_risk_criticality(RiskCriticality[value])
        self.update_widgets()
    
    def populate(self) -> ft.Container:
        checkboxes_split_point = round(len(self.checkboxes)/2)
        return ft.Container(
            alignment = ft.Alignment.CENTER,
            content= ft.Row(
                spacing = 5,
                controls=[
                    ft.Column(
                        margin = 15,
                        spacing = 15,
                        scroll = ft.ScrollMode.AUTO,
                        controls=[
                            ft.Column(
                                controls=[ # We use on_change instead of on_submit here. It's tremendously inefficient, but has no performance impact and prevents the user from losing their work by forgetting to press the Enter.
                                    ft.Text("Device Information", size=36, weight=ft.FontWeight.W_800),
                                    ft.Text(value="Name", expand=True, size=24, weight=ft.FontWeight.W_600),
                                    self.name_input,
                                    ft.Text(value="Vendor", expand=True, size=24, weight=ft.FontWeight.W_600),
                                    self.vendor_input,
                                    ft.Text(value="Release Year", expand=True, size=24, weight=ft.FontWeight.W_600),
                                    self.year_input,
                                    #self.weighted_checkbox,
                                ],
                                alignment=ft.MainAxisAlignment.START,
                                #visible=self.complete_mode,
                            ),
                            ft.Row(
                                controls=[
                                    ft.Text("Communications Protocols", size=36, weight=ft.FontWeight.W_800),
                                ],
                                alignment=ft.MainAxisAlignment.START,
                            ),
                            ft.Row(
                                controls=self.checkboxes[:checkboxes_split_point],
                                alignment=ft.MainAxisAlignment.START,
                            ),
                            ft.Row(
                                controls=self.checkboxes[checkboxes_split_point:],
                                alignment=ft.MainAxisAlignment.START,
                            ),
                            ft.Row(
                                controls=[
                                    ft.Text("Vulnerabilities", size=36, weight=ft.FontWeight.W_800),
                                    ft.Button("Add Vulnerability", on_click=self.on_add_vulnerability_prompt)
                                ],
                                alignment=ft.MainAxisAlignment.START,
                                vertical_alignment=ft.CrossAxisAlignment.CENTER
                            ),
                            ft.Row(
                                controls=[
                                    ft.Text("Insert vulnerability on the right, then press the button above.", size=16, weight=ft.FontWeight.W_600),
                                ],
                                alignment=ft.MainAxisAlignment.START,
                            ),
                            ft.Column(
                                spacing=10,
                                margin=10,
                                controls=self.vulnerability_widgets,
                                alignment=ft.MainAxisAlignment.CENTER,
                                horizontal_alignment=ft.CrossAxisAlignment.CENTER
                            )
                        ],
                    ),
                    ft.Column(
                        margin = 15,
                        spacing = 15,
                        scroll = ft.ScrollMode.AUTO,
                        controls=[
                            ft.Text("Risk Metrics", size=36, weight=ft.FontWeight.W_800),
                            ft.Text(value="Environment", expand=True, size=24, weight=ft.FontWeight.W_600),
                            self.environment_dropdown,
                            ft.Text(value="Criticality", expand=True, size=24, weight=ft.FontWeight.W_600),
                            self.criticality_dropdown,
                            ft.Text("Absolute IDSES Score", size=36, weight=ft.FontWeight.W_800),
                            self.main_idses_widget.populate(),
                            ft.Text("Risk-Adjusted IDSES Score", size=36, weight=ft.FontWeight.W_800),
                            self.weighted_idses_weidget.populate(),
                            ft.Text("IDSES Risk Matrix", size=36, weight=ft.FontWeight.W_800),
                            ft.Image(src="riskmatrix.png", width=500),
                            self.risk_acceptance_preamble[0],
                            self.risk_acceptance_result[0],
                        ]
                    ),
                    self.ivss_editor,
                ]
            )
        )
    